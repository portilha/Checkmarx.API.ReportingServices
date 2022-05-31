using Newtonsoft.Json;
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
    /// <summary>
    /// Based on the documentation of https://checkmarx.atlassian.net/wiki/spaces/RS/pages/5860130923/APIs
    /// </summary>
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

        #region Filter Helpers

        public FilterDTO GetTimeFrameFilter(DateTime startDateTime) => GetTimeFrameFilter(startDateTime, DateTime.Now);

        public FilterDTO GetTimeFrameFilter(DateTime startDateTime, DateTime endDate)
        {
            if (startDateTime > endDate)
                throw new ArgumentOutOfRangeException("The start date is after the end date");

            return new FilterDTO
            {
                Type = (int)FilterType.Timeframe,
                IncludedValues = new[] { startDateTime.ToString("yyyy-MM-dd"), endDate.ToString("yyyy-MM-dd") }
            };
        }

        #endregion

        #region Reports

        public Stream GetProjectReport(long projectId, string reportName, string format = "pdf", params FilterDTO[] filters)
        {
            if (projectId < 0)
                throw new ArgumentNullException(nameof(projectId));

            if (string.IsNullOrWhiteSpace(reportName))
                throw new ArgumentNullException(nameof(reportName));

            return getReportStream(new CreateReportDTO
            {
                EntityId = new string[] { projectId.ToString() },
                OutputFormat = format,
                ReportName = reportName,
                TemplateId = (int)TemplateType.ProjectTemplate,
                Filters = filters
            }, format).Stream;
        }

        public Stream GetApplicationReport(IEnumerable<long> projectIds, string reportName, string format = "pdf", params FilterDTO[] filters)
        {
            if (projectIds == null || projectIds.Count() <= 0)
                throw new ArgumentNullException(nameof(projectIds));

            if (string.IsNullOrWhiteSpace(reportName))
                throw new ArgumentNullException(nameof(reportName));

            return getReportStream(new CreateReportDTO
            {
                EntityId = projectIds.Select(x => x.ToString()).ToArray(),
                OutputFormat = format,
                ReportName = reportName,
                TemplateId = (int)TemplateType.Application,
                Filters = filters
            }, format).Stream;
        }

        public Stream GetTeamReport(string teamFullName, string reportName = null, string format = "pdf", params FilterDTO[] filters)
        {
            if (string.IsNullOrEmpty(teamFullName))
                throw new ArgumentNullException(nameof(teamFullName));

            return GetTeamReport(new string[] { teamFullName }, reportName, format, filters);
        }

        public Stream GetTeamReport(IEnumerable<string> teamsFullName, string reportName = null, string format = "pdf", params FilterDTO[] filters)
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

            return getReportStream(new CreateReportDTO
            {
                EntityId = teamsFullName.ToArray(),
                OutputFormat = format,
                ReportName = reportName,
                TemplateId = teamsFullName.Count() > 1 ? (int)TemplateType.MultiTeamsTemplate : (int)TemplateType.SingleTeamTemplate,
                Filters = filters
            }, format).Stream;
        }

        public Stream GetScanReportVulnerabilityTypeOriented(long scanId, string reportName, string format = "pdf", params FilterDTO[] filters)
        {
            return GetScanReport(scanId, reportName, format, TemplateType.ScanTemplateVulnerabilityTypeOriented, filters);
        }

        public Stream GetScanReportResultStateOriented(long scanId, string reportName, string format = "pdf", params FilterDTO[] filters)
        {
            return GetScanReport(scanId, reportName, format, TemplateType.ScanTemplateResultStateOriented, filters);
        }

        public Stream GetScanReport(long scanId, string reportName, string format = "pdf",
            TemplateType scanType = TemplateType.ScanTemplateVulnerabilityTypeOriented, params FilterDTO[] filters)
        {
            if (scanId < 0)
                throw new ArgumentNullException(nameof(scanId));

            if (string.IsNullOrWhiteSpace(reportName))
                throw new ArgumentNullException(nameof(reportName));

            if (scanType != TemplateType.ScanTemplateVulnerabilityTypeOriented &&
                scanType != TemplateType.ScanTemplateResultStateOriented)
                throw new ArgumentOutOfRangeException("The Scan report only support result state and vulnerability oriented report.");

            var finalFilters = filters ?? new FilterDTO[] { };

            return getReportStream(new CreateReportDTO
            {
                EntityId = new string[] { scanId.ToString() },
                OutputFormat = format,
                ReportName = reportName,
                TemplateId = (int)scanType,
                Filters = finalFilters
            }, format).Stream;
        }

        #endregion

        #region Report Helpers

        public string GetScanReportToFile(long scanId, string reportName, 
            TemplateType scanType = TemplateType.ScanTemplateVulnerabilityTypeOriented, 
            string format = "pdf", params FilterDTO[] filters)
        {
            string fileName = reportName + "." + format;

            return SaveReportToFile(
                GetScanReport(scanId, reportName, format, scanType, filters), 
                fileName);
        }

        public string SaveReportToFile(Stream result, string fileName)
        {
            using (FileStream fs = File.Create(fileName))
            {
                result.CopyTo(fs);
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

        #endregion
    }
}
