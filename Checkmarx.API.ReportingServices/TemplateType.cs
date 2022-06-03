namespace Checkmarx.API.ReportingServices
{
    public enum TemplateType : int
    {
        ScanTemplateVulnerabilityTypeOriented = 1,
        ScanTemplateResultStateOriented = 2,
        ProjectTemplate = 3,
        SingleTeamTemplate = 4,
        MultiTeamsTemplate = 5,
        Application = 6,
        Executive = 7
    }
}
