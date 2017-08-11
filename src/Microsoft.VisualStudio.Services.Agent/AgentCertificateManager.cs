using System;
using Microsoft.VisualStudio.Services.Agent.Util;
using System.IO;
using System.Runtime.Serialization;
using Microsoft.VisualStudio.Services.Common;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.VisualStudio.Services.Agent
{
    [ServiceLocator(Default = typeof(AgentCertificateManager))]
    public interface IAgentCertificateManager : IAgentService, IVssClientCertificateManager
    {
        string CACertificateFile { get; }
        string ClientCertificateFile { get; }
        string ClientCertificatePrivateKeyFile { get; }
        string ClientCertificateArchiveFile { get; }
        string ClientCertificatePassword { get; }
    }

    public class AgentCertificateManager : AgentService, IAgentCertificateManager
    {
        private readonly X509Certificate2Collection _clientCertificates = new X509Certificate2Collection();

        public override void Initialize(IHostContext hostContext)
        {
            base.Initialize(hostContext);
            LoadCertificateSettings();
        }

        // This should only be called from config
        public void SetupCertificate(string caCert, string clientCert, string clientCertPrivateKey, string clientCertArchive, string clientCertPassword)
        {
            ArgUtil.File(caCert, nameof(caCert));
            ArgUtil.File(clientCert, nameof(clientCert));
            ArgUtil.File(clientCertPrivateKey, nameof(clientCertPrivateKey));
            ArgUtil.File(clientCertArchive, nameof(clientCertArchive));
            ArgUtil.NotNullOrEmpty(clientCertPassword, nameof(clientCertPassword));

            Trace.Info("Setup agent certificate setting base on configuration inputs.");
            Trace.Info($"CA '{caCert}'");
            Trace.Info($"Client cert '{clientCert}'");
            Trace.Info($"Client cert private key '{clientCertPrivateKey}'");
            Trace.Info($"Client cert archive '{clientCertArchive}'");

            CACertificateFile = caCert;
            ClientCertificateFile = clientCert;
            ClientCertificatePrivateKeyFile = clientCertPrivateKey;
            ClientCertificateArchiveFile = clientCertArchive;
            ClientCertificatePassword = clientCertPassword;

            _clientCertificates.Clear();
            _clientCertificates.Add(new X509Certificate2(ClientCertificateArchiveFile, ClientCertificatePassword));
        }

        // This should only be called from config
        public void SaveCertificateSetting()
        {
            if (!string.IsNullOrEmpty(CACertificateFile) &&
                !string.IsNullOrEmpty(ClientCertificateFile) &&
                !string.IsNullOrEmpty(ClientCertificatePrivateKeyFile) &&
                !string.IsNullOrEmpty(ClientCertificateArchiveFile) &&
                !string.IsNullOrEmpty(ClientCertificatePassword))
            {
                string certSettingFile = IOUtil.GetAgentCertificateSettingFilePath();
                IOUtil.DeleteFile(certSettingFile);

                string lookupKey = Guid.NewGuid().ToString("D").ToUpperInvariant();
                Trace.Info($"Store client cert private key password with lookup key {lookupKey}");

                var credStore = HostContext.GetService<IAgentCredentialStore>();
                credStore.Write($"VSTS_AGENT_CLIENT_CERT_PASSWORD_{lookupKey}", "VSTS", ClientCertificatePassword);

                Trace.Info($"Store certificate settings to '{certSettingFile}'");
                var setting = new AgentCertificateSetting()
                {
                    CACert = CACertificateFile,
                    ClientCert = ClientCertificateFile,
                    ClientCertPrivatekey = ClientCertificatePrivateKeyFile,
                    ClientCertArchive = ClientCertificateArchiveFile,
                    ClientCertPasswordLookupKey = lookupKey
                };

                IOUtil.SaveObject(setting, certSettingFile);
                File.SetAttributes(certSettingFile, File.GetAttributes(certSettingFile) | FileAttributes.Hidden);
            }
            else
            {
                Trace.Info("No certificate setting found.");
            }
        }

        // This should only be called from unconfig
        public void DeleteCertificateSetting()
        {
            string certSettingFile = IOUtil.GetAgentCertificateSettingFilePath();
            if (File.Exists(certSettingFile))
            {
                Trace.Info($"Load agent certificate setting from '{certSettingFile}'");
                var certSetting = IOUtil.LoadObject<AgentCertificateSetting>(certSettingFile);

                if (certSetting != null && !string.IsNullOrEmpty(certSetting.ClientCertPasswordLookupKey))
                {
                    Trace.Info("Delete client cert private key password from credential store.");
                    var credStore = HostContext.GetService<IAgentCredentialStore>();
                    credStore.Delete($"VSTS_AGENT_CLIENT_CERT_PASSWORD_{certSetting.ClientCertPasswordLookupKey}");
                }

                Trace.Info($"Delete cert setting file: {certSettingFile}");
                IOUtil.DeleteFile(certSettingFile);
            }
        }

        public void LoadCertificateSettings()
        {
            string certSettingFile = IOUtil.GetAgentCertificateSettingFilePath();
            if (File.Exists(certSettingFile))
            {
                Trace.Info($"Load agent certificate setting from '{certSettingFile}'");
                var certSetting = IOUtil.LoadObject<AgentCertificateSetting>(certSettingFile);
                ArgUtil.NotNull(certSetting, nameof(AgentCertificateSetting));

                // make sure all settings exist                
                ArgUtil.File(certSetting.CACert, nameof(certSetting.CACert));
                ArgUtil.File(certSetting.ClientCert, nameof(certSetting.ClientCert));
                ArgUtil.File(certSetting.ClientCertPrivatekey, nameof(certSetting.ClientCertPrivatekey));
                ArgUtil.File(certSetting.ClientCertArchive, nameof(certSetting.ClientCertArchive));
                ArgUtil.NotNullOrEmpty(certSetting.ClientCertPasswordLookupKey, nameof(certSetting.ClientCertPasswordLookupKey));

                Trace.Info($"CA '{certSetting.CACert}'");
                CACertificateFile = certSetting.CACert;

                Trace.Info($"Client cert '{certSetting.ClientCert}'");
                ClientCertificateFile = certSetting.ClientCert;

                Trace.Info($"Client cert private key '{certSetting.ClientCertPrivatekey}'");
                ClientCertificatePrivateKeyFile = certSetting.ClientCertPrivatekey;

                Trace.Info($"Client cert archive '{certSetting.ClientCertArchive}'");
                ClientCertificateArchiveFile = certSetting.ClientCertArchive;

                var cerdStore = HostContext.GetService<IAgentCredentialStore>();
                ClientCertificatePassword = cerdStore.Read($"VSTS_AGENT_CLIENT_CERT_PASSWORD_{certSetting.ClientCertPasswordLookupKey}").Password;

                var secretMasker = HostContext.GetService<ISecretMasker>();
                secretMasker.AddValue(ClientCertificatePassword);

                _clientCertificates.Add(new X509Certificate2(ClientCertificateArchiveFile, ClientCertificatePassword));
            }
            else
            {
                Trace.Info("No certificate setting found.");
            }
        }

        public string CACertificateFile { private set; get; }
        public string ClientCertificateFile { private set; get; }
        public string ClientCertificatePrivateKeyFile { private set; get; }
        public string ClientCertificateArchiveFile { private set; get; }
        public string ClientCertificatePassword { private set; get; }

        public X509Certificate2Collection ClientCertificates => _clientCertificates;
    }

    [DataContract]
    internal class AgentCertificateSetting
    {
        [DataMember]
        public string CACert { get; set; }

        [DataMember]
        public string ClientCert { get; set; }

        [DataMember]
        public string ClientCertPrivatekey { get; set; }

        [DataMember]
        public string ClientCertArchive { get; set; }

        [DataMember]
        public string ClientCertPasswordLookupKey { get; set; }
    }
}
