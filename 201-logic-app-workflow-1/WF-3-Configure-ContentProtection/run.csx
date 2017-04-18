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
        log.Info("Asset found, Asset ID : " + assetid);

        if (!asset.ContentKeys.Any() && !asset.DeliveryPolicies.Any())
        {
            // Create envelope encryption content key
            Guid keyId = Guid.NewGuid();
            byte[] contentKey = GetRandomBuffer(16);

            IContentKey key = _context.ContentKeys.Create(
                                    keyId,
                                    contentKey,
                                    "ContentKey",
                                    ContentKeyType.CommonEncryption);

            // Associate the key with the asset.
            asset.ContentKeys.Add(key);
           
            AddOpenAuthorizationPolicy(key);
            CreateAssetDeliveryPolicy(asset, key);
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


public static void AddOpenAuthorizationPolicy(IContentKey contentKey)
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


public static void CreateAssetDeliveryPolicy(IAsset asset, IContentKey key)
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

    var assetDeliveryPolicy = _context.AssetDeliveryPolicies.Create(
            "AssetDeliveryPolicy",
        AssetDeliveryPolicyType.DynamicCommonEncryption,
        AssetDeliveryProtocol.Dash,
        assetDeliveryPolicyConfiguration);


    // Add AssetDelivery Policy to the asset
    asset.DeliveryPolicies.Add(assetDeliveryPolicy);

}


public static string ConfigurePlayReadyLicenseTemplate()
{
    // The following code configures PlayReady License Template using .NET classes
    // and returns the XML string.

    //The PlayReadyLicenseResponseTemplate class represents the template for the response sent back to the end user. 
    //It contains a field for a custom data string between the license server and the application 
    //(may be useful for custom app logic) as well as a list of one or more license templates.
    PlayReadyLicenseResponseTemplate responseTemplate = new PlayReadyLicenseResponseTemplate();

    // The PlayReadyLicenseTemplate class represents a license template for creating PlayReady licenses
    // to be returned to the end users. 
    //It contains the data on the content key in the license and any rights or restrictions to be 
    //enforced by the PlayReady DRM runtime when using the content key.
    PlayReadyLicenseTemplate licenseTemplate = new PlayReadyLicenseTemplate();
    //Configure whether the license is persistent (saved in persistent storage on the client) 
    //or non-persistent (only held in memory while the player is using the license).  
    licenseTemplate.LicenseType = PlayReadyLicenseType.Nonpersistent;

    // AllowTestDevices controls whether test devices can use the license or not.  
    // If true, the MinimumSecurityLevel property of the license
    // is set to 150.  If false (the default), the MinimumSecurityLevel property of the license is set to 2000.
    licenseTemplate.AllowTestDevices = true;

    // You can also configure the Play Right in the PlayReady license by using the PlayReadyPlayRight class. 
    // It grants the user the ability to playback the content subject to the zero or more restrictions 
    // configured in the license and on the PlayRight itself (for playback specific policy). 
    // Much of the policy on the PlayRight has to do with output restrictions 
    // which control the types of outputs that the content can be played over and 
    // any restrictions that must be put in place when using a given output.
    // For example, if the DigitalVideoOnlyContentRestriction is enabled, 
    //then the DRM runtime will only allow the video to be displayed over digital outputs 
    //(analog video outputs won’t be allowed to pass the content).

    //IMPORTANT: These types of restrictions can be very powerful but can also affect the consumer experience. 
    // If the output protections are configured too restrictive, 
    // the content might be unplayable on some clients. For more information, see the PlayReady Compliance Rules document.

    // For example:
    //licenseTemplate.PlayRight.AgcAndColorStripeRestriction = new AgcAndColorStripeRestriction(1);

    responseTemplate.LicenseTemplates.Add(licenseTemplate);

    return MediaServicesLicenseTemplateSerializer.Serialize(responseTemplate);
}

public static string ConfigureWidevineLicenseTemplate()
{
    var template = new WidevineMessage
    {
        allowed_track_types = AllowedTrackTypes.SD_HD,
        content_key_specs = new[]
        {
                    new ContentKeySpecs
                    {
                        required_output_protection = new RequiredOutputProtection { hdcp = Hdcp.HDCP_NONE},
                        security_level = 1,
                        track_type = "SD"
                    }
                },
        policy_overrides = new
        {
            can_play = true,
            can_persist = true,
            can_renew = false
        }
    };

    string configuration = JsonConvert.SerializeObject(template);
    return configuration;
}

private static byte[] GetRandomBuffer(int length)
{
    var returnValue = new byte[length];

    using (var rng =
        new System.Security.Cryptography.RNGCryptoServiceProvider())
    {
        rng.GetBytes(returnValue);
    }

    return returnValue;
}