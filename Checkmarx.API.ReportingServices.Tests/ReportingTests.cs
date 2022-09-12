using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using Utilities;

namespace Checkmarx.API.ReportingServices.Tests
{
    [TestClass]
    public class ReportingTests
    {
        private static ReportingServiceClient _client;


        private static CxClient _sastClient;

        public static IConfigurationRoot Configuration { get; private set; }


        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ReportingTests>();

            Configuration = builder.Build();

            _client = new ReportingServiceClient(Configuration["Server"], Configuration["SastServer"], Configuration["Username"], Configuration["Password"]);

            _sastClient = new CxClient(new Uri(Configuration["SastServer"]), Configuration["Username"], Configuration["Password"]);
        }


        [TestMethod]
        public void SASTConnectionTest()
        {
            Assert.IsTrue(_sastClient.Connected);
        }

        [TestMethod]
        public void AuthenticationTest()
        {
            Assert.IsNotNull(_client.ReportingService);
        }


        /// <summary>
        ///   "templateId": 1, Unique ID of a specific Template. Possible Values: 1 for Scan Template Vulnerability Type oriented; 2 for Scan Template Result State oriented; 3 for Project Template; 4 for Single Team Template; 5 for Multi Teams Template
        //"entityId": 100003, Unique ID.For the scan templates it is the Scan Id; for the project template it is the Project Id; for the teams templates it is the Team full name
        //"reportName": "Report Name", Name of the report to be generated.The service generates automatically a report Id that will be concatenated with the specified report name
        //"filters": [], Filters to be applied in the report creation.
        //Both reports accept as filters:
        //Severity, Result State and Status, which are build based on excludedValues. Severity: If not defined, Low and Informative results are excluded by default. Result State: If not defined, none is excluded by default.
        //Status: If not defined, Resolved is excluded by default. Specific Fiters for Scan Template: Query: Build based on excludedValues. If not defined none is excluded by default. Results Limit: Build based on includedValues, 5000 is the default limit.Specific Filters for Project Template: Timeframe: based on includedValues.To define a date range composed by a starting and an ending date.Data point: based on includedValues.By default last is used as data point. Allowed values are last or first.
        //Specific Fiters for Teams Templates: Project Name: Build based on excludedValues. If not defined none is excluded by default. Project Custom Fields: Build based on includedValues. If not defined no project is excluded by default.
        //Specific Fiters for Multi Teams Template: Team Name: Build based on excludedValues. If not defined none is excluded by default.
        //"outputFormat": "PDF" Format of the report to be generated.Is not case sensitive.
        /// </summary>
        [TestMethod]
        public void CreateScanReportTest()
        {
            var project = _sastClient.GetProjects().First();

            Trace.WriteLine($"{project.Key} {project.Value}");

            var scan = _sastClient.GetLastScan(project.Key);

            Assert.IsNotNull(scan);

            Trace.WriteLine(scan.Id);

            Stream fileName = _client.GetScanReport(scan.Id, project.Value + "_" + scan.Id);

            Trace.WriteLine(fileName);

            Assert.IsNotNull(fileName);
        }


        [TestMethod]
        public void MyTestMethod()
        {
            Stream fileName = _client.GetProjectReport(2, "test", "json");

            Trace.WriteLine(fileName);
        }

        [TestMethod]
        public void CreateProjectReportTest()
        {
            var project = _sastClient.GetProjects().First();

            try
            {
                Stream fileName = _client.GetProjectReport(project.Key, project.Value, "pdf");

                Trace.WriteLine(fileName);

                return;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(project.Value + "  " + ex.Message);
            }

        }

        [TestMethod]
        public void CreateTeamReportTest()
        {
            var team = _sastClient.AC.TeamsAllAsync().Result.First();

            Stream fileName = _client.GetTeamReport(new[] { team.FullName }, null, format: "pdf");
        }

        [TestMethod]
        public void CreateMultipleTeamReportTest()
        {
            var teams = _sastClient.AC.TeamsAllAsync().Result.Take(10);

            Stream fileName = _client.GetTeamReport(teams.Select(x => x.FullName).ToArray(), null, format: "pdf");
        }





        private Dictionary<int, string> _stateIdToName;
        public Dictionary<int, string> StateList
        {
            get
            {
                if (_stateIdToName == null)
                {
                    _stateIdToName = new Dictionary<int, string>();

                    foreach (var item in _sastClient.PortalSOAP.GetResultStateListAsync(null).Result.ResultStateList)
                    {
                        _stateIdToName.Add((int)item.ResultID, item.ResultName);
                    }
                }

                return _stateIdToName;
            }
        }


        [TestMethod]
        public void GetProjectDetails()
        {
            var project = _sastClient.GetProjectSettings(2);

            var sastCustomFields = _sastClient.GetSASTCustomFields();

            int asaStatus = sastCustomFields["ASA_Status"];
            int optimizationDate = sastCustomFields["ASA_Status"];

            foreach (var customField in project.CustomFields)
            {
                Trace.WriteLine(customField.Id + " = " + customField.Value);
            }

            Trace.WriteLine(_sastClient.GetProjectTeamName(project.TeamId));
        }

        [TestMethod]
        public void GetJsonReportFromScanTemplateVulnerabilityTypeOrientedForProjectTest()
        {
            int projectId = 2;

           

            StringBuilder scansInfo = new StringBuilder("\"" + string.Join("\",\"",
                "Project Id",
                "Team",
                "Scan Id",
                "Scan Date",
                "isIncremental",
                "vulnerabilityType",
                "queryPath",
                "Query Name",
                "hyperlink",
                "hyperlinkScanId",
                "hyperlinkPathId",
                "similarityId",
                "State",
                "level",
                "firstDetection",
                //"optimizationDate",
                "resolvedDate",
                "timeToResolve") + "\"\r\n");

            var queries = _sastClient.GetQueries().SelectMany(x => x.Queries).ToDictionary(x => x.QueryVersionCode);

            foreach (var scan in _sastClient.GetScans(projectId, true))
            {
                try
                {
                    scansInfo.Append(GetFixedResultsTest(scan, queries));
                }
                catch (Exception ex)
                {
                    Trace.WriteLine(ex.Message);
                }

                //string file = _client.GetScanReportToFile(scan.Id, $"{projectId}_{scan.Id}_ScanTemplateVulnerabilityTypeOriented",
                //    TemplateType.ScanTemplateVulnerabilityTypeOriented, "json",
                //    new FilterDTO
                //    {
                //        Type = 5,
                //        ExcludedValues = new string[] { }
                //    });
                // Trace.WriteLine(file);
            }

            string file = $"scan_{DateTime.Now.Ticks}.csv";

            File.WriteAllText(file, scansInfo.ToString());

            ProcessUtils.ShowFileInExplorer(file);
        }

        [TestMethod]
        public void GetJsonReportFromScanTemplateVulnerabilityTypeOrientedForSingleScanTest()
        {
            long scanId = 1001335;

            string file = _client.GetScanReportToFile(scanId, scanId.ToString(), TemplateType.ScanTemplateVulnerabilityTypeOriented, "json",
                    new FilterDTO
                    {
                        Type = (int)FilterType.ResultStatus, // result state
                        ExcludedValues = new string[] { }
                    },
                     new FilterDTO
                     {
                         Type = (int)FilterType.Severity, // 
                         ExcludedValues = new string[] { }
                     },
                     new FilterDTO
                     {
                         Type = (int)FilterType.ResultState, // 
                         ExcludedValues = new string[] { }
                     },
                     new FilterDTO
                     {
                         Type = (int)FilterType.ResultsLimit, // number of vulnerablities
                         IncludedValues = new string[] { "1000000" }
                     });

            Trace.WriteLine(file);

            ProcessUtils.ShowFileInExplorer(file);
        }

        public StringBuilder GetFixedResultsTest(SAST.Scan scan, Dictionary<long, cxPortalWebService93.CxWSQuery> queries)
        {
            StringBuilder sb = new StringBuilder();

            var report = _client.GetJsonFromReport(_client.GetScanReportVulnerabilityTypeOriented(scan.Id, scan.Id.ToString(), "json",
                   new FilterDTO
                   {
                       Type = (int)FilterType.ResultStatus, // result state
                       ExcludedValues = new string[] { }
                   },
                    new FilterDTO
                    {
                        Type = (int)FilterType.Severity, // 
                        ExcludedValues = new string[] { }
                    },
                    new FilterDTO
                    {
                        Type = (int)FilterType.ResultState, // 
                        ExcludedValues = new string[] { }
                    },
                    new FilterDTO
                    {
                        Type = (int)FilterType.ResultsLimit, // number of vulnerablities
                        IncludedValues = new string[] { "1000000" }
                    }));

            Assert.IsNotNull(report);

            if (report.resolvedVulnerabilities != null)
            {
                int total = (int)report.resolvedVulnerabilities.total;

                if (total > 0)
                {
                    foreach (var vulnType in report.resolvedVulnerabilities.vulnerabilitiesList)
                    {
                        foreach (var result in vulnType.results)
                        {
                            foreach (var resolved in result.resolved)
                            {
                                Uri hiperlink = (Uri)resolved.hyperlink;

                                string[] hyperlinkParameters = hiperlink.Query.Remove(0, 1).Split("&");

                                long hyperlinkScanId = long.Parse(hyperlinkParameters[0].Split("=")[1]);
                                int hyperlinkPathId = int.Parse(hyperlinkParameters[2].Split("=")[1]);
                                var scanResult = GetResult(hyperlinkScanId, hyperlinkPathId);

                                long queryVersion = (long)vulnType.queryVersion;

                                string queryName = $"{queryVersion} found not";
                                if (queries.ContainsKey(queryVersion))
                                    queryName = queries[queryVersion].Name;

                                sb.AppendLine(
                                     String.Join(",",
                                     scan.Id,
                                     scan.DateAndTime?.EngineStartedOn,
                                     scan.IsIncremental,
                                     (string)vulnType.vulnerabilityType,
                                     (string)vulnType.queryPath,
                                     queryName,
                                     hiperlink.AbsoluteUri,
                                     hyperlinkScanId,
                                     hyperlinkPathId,
                                     scanResult.SimilarityId,
                                     StateList[scanResult.StateId],
                                     (string)resolved.level,
                                     (DateTime)resolved.firstDetection,
                                     (DateTime)resolved.resolvedDate,
                                     (int)resolved.timeToResolve
                                     ));
                            }
                        }
                    }
                }
            }
            return sb;
        }

        private Dictionary<long, Dictionary<long, CxDataRepository.Result>> _resultsCache = new Dictionary<long, Dictionary<long, CxDataRepository.Result>>();

        private CxDataRepository.Result GetResult(long hyperlinkScanId, int hyperlinkPathId)
        {
            Dictionary<long, CxDataRepository.Result> scanResults = null;
            if (!_resultsCache.ContainsKey(hyperlinkScanId))
            {
                scanResults = _sastClient.GetODataResults(hyperlinkScanId).ToDictionary(x => x.PathId);
                _resultsCache.Add(hyperlinkScanId, scanResults);
            }

            return _resultsCache[hyperlinkScanId][hyperlinkPathId];
        }

        [TestMethod]
        public void GetScanDiffTest()
        {
            var fixResults = _sastClient.GetScansDiff(1000006, 1001335)
                .Where(x => x.ResultStatus == cxPortalWebService93.CompareStatusType.Fixed);

            Trace.WriteLine(fixResults.Count());
        }

        [TestMethod]
        public void GetSimilarityIdTest()
        {
            foreach (var item in _sastClient.GetODataResults(1000006).Where(x => x.PathId == 1))
            {
                Trace.WriteLine("similiarity=" + item.SimilarityId);
                Trace.WriteLine("scanid=" + item.ScanId);
                Trace.WriteLine("pathid=" + item.PathId);
                Trace.WriteLine(item.Comment);
            }
        }



        [TestMethod]
        public void GetOnboardedPRojectTest()
        {
            foreach (var item in _sastClient.GetProjects())
            {
                foreach (var cf in _sastClient.GetProjectCustomFields(item.Key))
                {
                    if (cf.Value.Value == "Delivered")
                    {
                        Trace.WriteLine(item.Key + " " + item.Value);
                        break;
                    }
                }
            }
        }


        [TestMethod]
        public void GetScansFromPRojectTest()
        {
            foreach (var item in _sastClient.GetScans(2, true))
            {
                Trace.WriteLine(item.Id);
            }
        }


        [TestMethod]
        public void GetProjectTest()
        {
            var st = _client.GetProjectReport(2, "projectreport_2", "pdf");

            string fileName = "testPDF.pdf";

            using (FileStream fs = File.Create(fileName))
            {
                st.CopyTo(fs);
            }

            Trace.WriteLine(Path.GetFullPath(fileName));
        }

        [TestMethod]
        public void ValidateRSVersionTest()
        {
            Assert.IsTrue(_client.SupportsRESTAPIVersion(2));
        }

        [TestMethod]
        public void ValidateRSVersionFailTest()
        {
            Assert.IsFalse(_client.SupportsRESTAPIVersion(4));
        }



        [TestMethod]
        public void GetStatechangestest()
        {
            var result = _sastClient.PortalSOAP.GetPathCommentsHistoryAsync(string.Empty, 1001357, 11,  cxPortalWebService93.ResultLabelTypeEnum.State).Result;


            Assert.IsNotNull(result);
        }

    }
}
