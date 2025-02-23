rule DetectMaliciousPDF
{
    meta:
        description = "Detect potentially malicious PDFs"
        author = "Your Name"
    strings:
        $pdf_header = "%PDF"
        $malicious_keyword = "javascript"
        $exploit_code = "/JS"
    condition:
        $pdf_header and ($malicious_keyword or $exploit_code)
}
