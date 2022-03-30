namespace Checkmarx.API.ReportingServices
{
    /// <summary>
    /// Filters to be applied in the report creation. 
    /// Types of filters:
    /// </summary>
    public enum FilterType : int
    {
        //  1 - Severity:
        //  Build based on excludedValues.
        //  If not defined, Low and Informative results are excluded by default.
        //  Applicable for all report types.
        // Excluding results having severity = Information and Low.
        // "excludedValues": ["Information", "Low"]
        Severity = 1,
        //  2 - Result State:
        //  Build based on excludedValues.
        //  If not defined, none is excluded by default.
        //  Applicable for all report types.
        // Not Exploitable Result state will be excluded.
        // "excludedValues": ["Not Exploitable"]
        ResultState = 2,
        //  3 - Query/Vulnerability:
        //  Build based on excludedValues.
        //  If not defined none is excluded by default.
        //  Applicable for the Scan Template only.
        // Excluding SQL Injection
        // "excludedValues": [ "SQL_Injection" ]
        Query = 3,
        //  4 - Timeframe:
        //  Build based on includedValues.
        //  To define a date range composed by a starting and an ending date.
        //  Applicable for all report types with the exception of the Scan Template.
        //  Setting timeframe with included values between January 1 and November16.
        //  "includedValues": ["2021-01-01","2021-11-16" ] 
        Timeframe = 4,
        //  5 - Status:
        //  Build based on excludedValues.
        //  If not defined, Resolved is excluded by default.
        //  Applicable for all report types.
        // Excluding New findings
        // "excludedValues": [ "New" ] 
        ResultStatus = 5,
        //  6 - Results Limit:
        //  Build based on includedValues, 5000 is the default limit.
        //  Applicable for the Scan Template only.
        // Including the Limit Results to be printed in Scan Results section to 100
        // "includedValues": [ "100" ]
        // default 5000, 
        ResultsLimit = 6,
        //  7 - Data Point:
        //  Build based on includedValues.
        //  By default last is used as data point.
        //  Allowed values are last or first.
        //  Applicable for all report types with the exception of the Scan Template.
        //  Setting data point as first, Allow first or last
        //  "includedValues": ["first"]
        DataPoint = 7,
        // 8 - Project Name:
        // Build based on excludedValues.
        // If not defined none is excluded by default.
        // Applicable for Teams templates.
        // Include or exclude based on Project Name
        // "excludedValues": ["BookStoreJava"]
        ProjectName = 8,
        // 9 - Project Custom Fields:
        // Build based on includedValues.
        // If not defined no project is excluded by default.
        // Applicable for Teams and Application templates.
        // Include or exclude based on custom field
        // "includedValues": ["Version","1"]
        ProjectCustomFields = 9
    }
}
