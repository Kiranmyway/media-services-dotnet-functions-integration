#r "Newtonsoft.Json"
#r "Microsoft.WindowsAzure.Storage"
#r "System.Web"

#load "../Shared/mediaServicesHelpers.csx"
#load "../Shared/ingestAssetConfigHelpers.csx"

using System;
using System.Net;
using System.Web;
using Newtonsoft.Json;
using Microsoft.WindowsAzure.MediaServices.Client;
using Microsoft.WindowsAzure.MediaServices.Client.ContentKeyAuthorization;
using Microsoft.WindowsAzure.MediaServices.Client.DynamicEncryption;
using Microsoft.WindowsAzure.MediaServices.Client.FairPlay;
using Microsoft.WindowsAzure.MediaServices.Client.Widevine;
using Microsoft.WindowsAzure.Storage;


// Read values from the App.config file.
private static readonly string _mediaServicesAccountName = Environment.GetEnvironmentVariable("AMSAccount");
private static readonly string _mediaServicesAccountKey = Environment.GetEnvironmentVariable("AMSKey");

// Field for service context.
private static CloudMediaContext _context = null;
private static CloudStorageAccount _destinationStorageAccount = null;


public static async Task<object> Run(HttpRequestMessage req, TraceWriter log)
{
    log.Info($"Webhook was triggered!");
    string jsonContent = await req.Content.ReadAsStringAsync();
    dynamic data = JsonConvert.DeserializeObject(jsonContent);
    log.Info("Request : " + jsonContent);

    // Validate input objects
    if (data.AssetId == null)
        return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass AssetId in the input object" });
    if (data.IngestAssetConfigJson == null)
        return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass IngestAssetConfigJson in the input object" });
    log.Info("Input - Asset Id : " + data.AssetId);
    log.Info("Input - IngestAssetConfigJson : " + data.IngestAssetConfigJson);

    string assetid = data.AssetId;
    string ingestAssetConfigJson = data.IngestAssetConfigJson;
    IngestAssetConfig config = ParseIngestAssetConfig(ingestAssetConfigJson);
    if (!ValidateIngestAssetConfig(config))
        return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass a valid IngestAssetConfig as FileContent" });
    log.Info("Input - Valid IngestAssetConfig was loaded.");


    IJob job = null;
    IAsset outputAsset = null;
    try
    {
        // Load AMS account context
        log.Info("Using Azure Media Services account : " + _mediaServicesAccountName);
        _context = new CloudMediaContext(new MediaServicesCredentials(_mediaServicesAccountName, _mediaServicesAccountKey));

        // Get the Asset
        var asset = _context.Assets.Where(a => a.Id == assetid).FirstOrDefault();
        if (asset == null)
        {
            log.Info("Asset not found - " + assetid);
            return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Asset not found" });
        }
        log.Info("Asset found, Asset ID : " + asset.Id);

        if (!asset.ContentKeys.Any() && !asset.DeliveryPolicies.Any())
        {
            // Create envelope encryption content key
            Guid keyId = Guid.NewGuid();
            byte[] contentKey = GetRandomBuffer(16);

            IContentKey key = _mediaContext.ContentKeys.Create(
                                    keyId,
                                    contentKey,
                                    "ContentKey",
                                    ContentKeyType.CommonEncryption);

            // Associate the key with the asset.
            asset.ContentKeys.Add(key);
           
            AddOpenAuthorizationPolicy(key);
            CreateAssetDeliveryPolicy(assetId, key);
        }
    }
    catch (Exception ex)
    {
        log.Info("Exception " + ex);
        return req.CreateResponse(HttpStatusCode.BadRequest);
    }

    return req.CreateResponse(HttpStatusCode.OK, new
    {
        AssetId = asset.Id,
    });
}


public void AddOpenAuthorizationPolicy(IContentKey contentKey)
{

    // Create ContentKeyAuthorizationPolicy with Open restrictions 
    // and create authorization policy          

    List<ContentKeyAuthorizationPolicyRestriction> restrictions = new List<ContentKeyAuthorizationPolicyRestriction>
            {
                new ContentKeyAuthorizationPolicyRestriction
                {
                    Name = "Open",
                    KeyRestrictionType = (int)ContentKeyRestrictionType.Open,
                    Requirements = null
                }
            };

    // Configure PlayReady and Widevine license templates.
    string playReadyLicenseTemplate = ConfigurePlayReadyLicenseTemplate();

    string widevineLicenseTemplate = ConfigureWidevineLicenseTemplate();

    IContentKeyAuthorizationPolicyOption playReadyPolicy =
        _context.ContentKeyAuthorizationPolicyOptions.Create("",
            ContentKeyDeliveryType.PlayReadyLicense,
                restrictions, playReadyLicenseTemplate);

    IContentKeyAuthorizationPolicyOption widevinePolicy =
        _context.ContentKeyAuthorizationPolicyOptions.Create("",
            ContentKeyDeliveryType.Widevine,
            restrictions, widevineLicenseTemplate);

    IContentKeyAuthorizationPolicy contentKeyAuthorizationPolicy = _context.
                ContentKeyAuthorizationPolicies.
                CreateAsync("Deliver Common Content Key with no restrictions").
                Result;


    contentKeyAuthorizationPolicy.Options.Add(playReadyPolicy);
    contentKeyAuthorizationPolicy.Options.Add(widevinePolicy);
    // Associate the content key authorization policy with the content key.
    contentKey.AuthorizationPolicyId = contentKeyAuthorizationPolicy.Id;
    contentKey = contentKey.UpdateAsync().Result;
}


public void CreateAssetDeliveryPolicy(IAsset asset, IContentKey key)
{

    // Get the PlayReady license service URL.
    Uri acquisitionUrl = key.GetKeyDeliveryUrl(ContentKeyDeliveryType.PlayReadyLicense);

    // GetKeyDeliveryUrl for Widevine attaches the KID to the URL.
    // For example: https://amsaccount1.keydelivery.mediaservices.windows.net/Widevine/?KID=268a6dcb-18c8-4648-8c95-f46429e4927c.  
    // The WidevineBaseLicenseAcquisitionUrl (used below) also tells Dynamaic Encryption 
    // to append /? KID =< keyId > to the end of the url when creating the manifest.
    // As a result Widevine license aquisition URL will have KID appended twice, 
    // so we need to remove the KID that in the URL when we call GetKeyDeliveryUrl.

    Uri widevineUrl = key.GetKeyDeliveryUrl(ContentKeyDeliveryType.Widevine);
    UriBuilder uriBuilder = new UriBuilder(widevineUrl);
    uriBuilder.Query = String.Empty;
    widevineUrl = uriBuilder.Uri;

    Dictionary<AssetDeliveryPolicyConfigurationKey, string> assetDeliveryPolicyConfiguration =
        new Dictionary<AssetDeliveryPolicyConfigurationKey, string>
        {
                    {AssetDeliveryPolicyConfigurationKey.PlayReadyLicenseAcquisitionUrl, acquisitionUrl.ToString()},
                    {AssetDeliveryPolicyConfigurationKey.WidevineBaseLicenseAcquisitionUrl, widevineUrl.ToString()}

        };

    var assetDeliveryPolicy = _mediaContext.AssetDeliveryPolicies.Create(
            "AssetDeliveryPolicy",
        AssetDeliveryPolicyType.DynamicCommonEncryption,
        AssetDeliveryProtocol.Dash,
        assetDeliveryPolicyConfiguration);


    // Add AssetDelivery Policy to the asset
    asset.DeliveryPolicies.Add(assetDeliveryPolicy);

}