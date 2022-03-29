﻿using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;

namespace Checkmarx.API.ReportingServices
{

    enum TemplateType : int
    {
        ScanTemplateVulnerabilityTypeOriented = 1,
        ScanTemplateResultStateOriented = 2,
        ProjectTemplate = 3,
        SingleTeamTemplate = 4,
        MultiTeamsTemplate = 5
    }

    

    public enum FilterType : int
    {
        // Excluding results having severity = Information and Low.
        // "excludedValues": ["Information", "Low"] - 
        Severity = 1,
        // Not Exploitable Result state will be excluded.
        // "excludedValues": ["Not Exploitable"]
        ResultState = 2,
        // Excluding SQL Injection
        // "excludedValues": [ "SQL_Injection" ]
        Query = 3,
        //  Setting timeframe with included values between January 1 and November16.
        //  "includedValues": ["2021-01-01","2021-11-16" ] 
        TimeFrame = 4,
        // Excluding New findings
        // "excludedValues": [ "New" ] 
        ResultStatus = 5,
        // Including the Limit Results to be printed in Scan Results section to 100
        // "includedValues": [ "100" ]
        // default 5000, 
        NumberOfResults = 6, 
        //  Setting data point as first
        //  "includedValues": ["first"]
        DataPointOrder = 7,
        // Include or exclude based on Project Name
        // "excludedValues": ["BookStoreJava"]
        Projects = 8,
        // Include or exclude based on custom field
        // "includedValues": ["Version","1"]
        CustomFields = 9
    }

    public class ReportingServiceClient
    {
        private Uri _acUrl;
        private Uri _baseURL;

        private string _username;
        private string _password;

        private readonly HttpClient _httpClient = new HttpClient();
        private readonly HttpClient _acHttpClient = new HttpClient();


        /// <summary>
        /// Pooling interval in seconds for the conclusion of the report
        /// </summary>
        public int PoolingInterval { get; set; } = 2;

        private DateTime _bearerValidTo;


        private AccessControlClient _ac = null;
        public AccessControlClient AC
        {
            get
            {
                if (_ac == null && ReportingService != null)
                {
                    _ac = new AccessControlClient(_acHttpClient)
                    {
                        BaseUrl = _acUrl.AbsoluteUri
                    };
                }
                return _ac;
            }
        }

        public ReportingServiceClient(string reportingServerUrl, string acUrl, string username,
            string password)
        {
            if (string.IsNullOrEmpty(reportingServerUrl)) throw new ArgumentNullException(nameof(reportingServerUrl));
            if (string.IsNullOrEmpty(acUrl)) throw new ArgumentNullException(nameof(acUrl));
            if (string.IsNullOrEmpty(username)) throw new ArgumentNullException(nameof(username));
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));

            _username = username;
            _password = password;
            _acUrl = new Uri(acUrl);
            _baseURL = new Uri(reportingServerUrl);
        }

        private ReportingService _reportingService = null;

        public ReportingService ReportingService
        {
            get
            {
                if (_reportingService == null || (_bearerValidTo - DateTime.UtcNow).TotalMinutes < 5)
                {
                    var token = Autenticate(_username, _password);
                    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    _acHttpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

                    _reportingService = new ReportingService(_baseURL.AbsoluteUri, _httpClient);

                    _bearerValidTo = DateTime.UtcNow.AddHours(1);
                }
                return _reportingService;
            }
        }

        private string Autenticate(string username, string password)
        {
            var identityURL = $"{_acUrl}CxRestAPI/auth/identity/connect/token";
            var kv = new Dictionary<string, string>
            {
                { "grant_type", "password" },
                { "client_id", "reporting_service_api" },
                { "scope", "reporting_api" },
                { "username", username },
                { "password", password }
            };


            var req = new HttpRequestMessage(HttpMethod.Post, identityURL) { Content = new FormUrlEncodedContent(kv) };
            req.Headers.Add("Accept", "application/json");

            var response = _httpClient.SendAsync(req).Result;
            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                JObject accessToken = JsonConvert.DeserializeObject<JObject>(response.Content.ReadAsStringAsync().Result);
                string authToken = ((JProperty)accessToken.First).Value.ToString();
                return authToken;
            }
            throw new Exception(response.Content.ReadAsStringAsync().Result);
        }

        public string GetProjectReport(long projectId, string reportName, string format = "pdf")
        {
            if (projectId < 0)
                throw new ArgumentNullException(nameof(projectId));

            if (string.IsNullOrWhiteSpace(reportName))
                throw new ArgumentNullException(nameof(reportName));

            return getReportFile(new CreateReportDTO
            {
                EntityId = new string[] { projectId.ToString() },
                OutputFormat = format,
                ReportName = reportName,
                TemplateId = (int)TemplateType.ProjectTemplate
            }, format);
        }

        public string GetTeamReport(string reportName, string format = "pdf", params string[] teamsFullName)
        {
            if (teamsFullName == null || !teamsFullName.Any())
                throw new ArgumentNullException(nameof(teamsFullName));

            if (string.IsNullOrEmpty(reportName))
            {
                if (teamsFullName.Count() == 1)
                    reportName = teamsFullName.Single().Split("/").Last();
                else
                    reportName = "MultipleTeams";
            }

            return getReportFile(new CreateReportDTO
            {
                EntityId = teamsFullName,
                //Filters = new FilterDTO[] {
                //    new FilterDTO
                //    {
                //        Type = (int)FilterType.Severity,
                        
                //    }
                //},
                OutputFormat = format,
                ReportName = reportName,
                TemplateId = teamsFullName.Count() > 1 ? (int)TemplateType.MultiTeamsTemplate : (int)TemplateType.SingleTeamTemplate
            }, format);
        }

        public string GetScanReport(long scanId, string reportName, string format = "pdf")
        {
            if (scanId < 0)
                throw new ArgumentNullException(nameof(scanId));

            if (string.IsNullOrWhiteSpace(reportName))
                throw new ArgumentNullException(nameof(reportName));

            return getReportFile(new CreateReportDTO
            {
                EntityId = new string[] { scanId.ToString() },
                OutputFormat = format,
                ReportName = reportName,
                TemplateId = (int)TemplateType.ScanTemplateVulnerabilityTypeOriented
            }, format);
        }

        public Stream GetScanReportVulnerabilityTypeOriented(long scanId, string reportName, string format = "pdf")
        {
            return GetScanReportStream(scanId, reportName, format, TemplateType.ScanTemplateVulnerabilityTypeOriented);
        }

        public Stream GetScanReportResultStateOriented(long scanId, string reportName, string format = "pdf")
        {
            return GetScanReportStream(scanId, reportName, format, TemplateType.ScanTemplateResultStateOriented);
        }

        private Stream GetScanReportStream(long scanId, string reportName, string format = "pdf",
            TemplateType templateType = TemplateType.ScanTemplateVulnerabilityTypeOriented)
        {
            if (scanId < 0)
                throw new ArgumentNullException(nameof(scanId));

            if (string.IsNullOrWhiteSpace(reportName))
                throw new ArgumentNullException(nameof(reportName));

            if (templateType != TemplateType.ScanTemplateVulnerabilityTypeOriented &&
                templateType != TemplateType.ScanTemplateResultStateOriented)
                throw new ArgumentOutOfRangeException("The Scan report only support result state and vulnerability oriented report.");

            return getReportStream(new CreateReportDTO
            {
                EntityId = new string[] { scanId.ToString() },
                OutputFormat = format,
                ReportName = reportName,
                TemplateId = (int)templateType
            }, format).Stream;
        }


        private string getReportFile(CreateReportDTO report, string format)
        {
            var result = getReportStream(report, format);

            string fileName = report.ReportName + "." + format;

            using (FileStream fs = File.Create(fileName))
            {
                result.Stream.CopyTo(fs);
            }

            return Path.GetFullPath(fileName);
        }

        private FileResponse getReportStream(CreateReportDTO report, string format)
        {
            format = format?.ToLowerInvariant().Trim();

            if (format != "pdf" && format != "json")
                throw new ArgumentOutOfRangeException("The format can only be json or pdf");

            var createReport = this.ReportingService.CreateReportAsync(report).Result;
            var statys = ReportingService.ReportStatusAsync(createReport.ReportId).Result;
            while (statys.ReportStatus == "Processing")
            {
                Thread.Sleep(System.TimeSpan.FromSeconds(PoolingInterval));
                statys = ReportingService.ReportStatusAsync(createReport.ReportId).Result;
            }

            Console.WriteLine(statys.ReportStatus);

            if (statys.ReportStatus == "Failed")
                throw new ApplicationException(statys.Message);

            return ReportingService.ReportsGETAsync(createReport.ReportId).Result;
        }
    }
}
