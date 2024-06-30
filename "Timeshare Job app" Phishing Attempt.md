**Identifying and Analyzing Phishing Attempts in PDFs**
Phishing is a common tactic used by cybercriminals to deceive individuals into providing personal information or engaging in further malicious activities. One of the mediums used for such attacks is PDF files. In this write-up, we will discuss how to identify potential phishing attempts in PDFs and present an analysis of a suspicious PDF file titled "Timeshare Resales Hawaii JOB SUMMARY.pdf."

**Introduction**
Recently, a suspicious PDF file titled "Timeshare Resales Hawaii JOB SUMMARY.pdf" was analyzed to identify potential phishing attempts. This analysis involved inspecting the PDF for embedded scripts, suspicious links, and any other signs of malicious activity.

**Analysis Process**
The analysis was performed using various tools, including pdf-parser.py and YARA rules. Here is a detailed breakdown of the process and findings.

**Step 1: Initial Inspection**
The initial inspection involved examining the PDF's metadata and structure using pdf-parser.py. The following key points were noted:

The PDF was created using Microsoft® Word 2013.
The creation and modification dates were recent, which could be a red flag for phishing attempts.

**Step 2:** Searching for Suspicious Elements
To identify any embedded scripts or actions, specific searches were conducted within the PDF:

JavaScript: No embedded JavaScript was found.
OpenAction: No OpenAction commands were found.
Launch Actions: No Launch actions were found.
URI Links: Two mailto links were found.
Identified Suspicious Links
Two mailto links were identified within the PDF, which could potentially be used for phishing:

mailto
@timeshareresaleshawaii.team

This link prompts the email client to compose an email to jseamster@timeshareresaleshawaii.team.
The domain timeshareresaleshawaii.team was newly registered, making it suspicious.
mailto:%20candice@csvnow.team

This link prompts the email client to compose an email to candice@csvnow.team.
The domain csvnow.team is also suspicious.

**Step 3:** Using YARA Rules
YARA rules were used to scan the PDF for known malicious patterns. The rules targeted elements such as JavaScript, OpenAction, Launch actions, and URI links. The scan resulted in a match for suspicious patterns, specifically due to the presence of the mailto links.

**Conclusion**
The PDF file "Timeshare Resales Hawaii JOB SUMMARY.pdf" does not contain direct malicious scripts or actions but includes suspicious mailto links that could be used for phishing. Here are the key takeaways:

**Phishing Risk:** The primary risk identified is phishing through the mailto links.
Avoid Interaction: Do not interact with the links or send emails to the addresses provided in the PDF.
Report and Delete: Report the email as phishing and delete the email and PDF to avoid accidental interaction.
**Recommendations**
Be Cautious with Email Links:

Always verify the authenticity of unsolicited emails, especially those containing attachments or links.
Report Suspicious Emails:
Report suspicious emails as phishing to your email provider.

Educate on Phishing:
Educate yourself and others about phishing tactics and how to recognize them.

**Final Thoughts**
While the PDF did not contain direct executable malware, the presence of mailto links suggests a potential phishing attempt. By following the outlined steps and staying vigilant, you can protect yourself from such threats.

-------------------------------------------------------------------------------------------------------------------------------------

**Techniques Used in Phishing and Malware Analysis**
In my analysis of phishing attempts and malicious PDFs, we employ several key techniques to uncover and understand the threats. Below, I outline these techniques and provide example scripts to illustrate how you can apply them in your own investigations.

**1. Metadata Analysis**
We use tools like pdf-parser.py and exiftool to inspect the metadata of files, gathering information about their origin, creation date, and other properties.
pdf-parser.py can be found here(https://github.com/DidierStevens/DidierStevensSuite)

Example: Analyzing PDF Metadata:
python pdf-parser.py -a "Timeshare Resales Hawaii JOB SUMMARY.pdf"

**2. Static Analysis**
Static analysis involves examining the content of a file without executing it, looking for embedded scripts, suspicious patterns, and links.

Example: Searching for Suspicious Patterns:
python pdf-parser.py --search /JavaScript "Timeshare Resales Hawaii JOB SUMMARY.pdf"
python pdf-parser.py --search /OpenAction "Timeshare Resales Hawaii JOB SUMMARY.pdf"
python pdf-parser.py --search /Launch "Timeshare Resales Hawaii JOB SUMMARY.pdf"
python pdf-parser.py --search /URI "Timeshare Resales Hawaii JOB SUMMARY.pdf"

**3. YARA Rules**
I use YARA rules to identify and classify malware based on known patterns.

Example YARA Rule:
rule PDF_JavaScript
{
    strings:
        $js = /\/JavaScript/ nocase
    condition:
        $js
}

rule PDF_OpenAction
{
    strings:
        $openAction = /\/OpenAction/ nocase
    condition:
        $openAction
}

rule PDF_Launch
{
    strings:
        $launch = /\/Launch/ nocase
    condition:
        $launch
}

rule PDF_SuspiciousPatterns
{
    strings:
        $js = /\/JavaScript/ nocase
        $openAction = /\/OpenAction/ nocase
        $launch = /\/Launch/ nocase
        $uri = /\/URI/ nocase
    condition:
        $js or $openAction or $launch or $uri
}

**Python script to run the YARA rules:**
import yara

rules = yara.compile(filepath='example_rule.yar')
matches = rules.match('Timeshare Resales Hawaii JOB SUMMARY.pdf')

for match in matches:
    print(f'Match: {match.rule}')
