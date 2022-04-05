using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

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
    }
}
