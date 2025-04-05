# Phishing Email Detected - Excel 4.0 Macros

## Objective
The purpose of this project was to analyze a phishing email that activated a harmful Excel 4.0 macro. The investigation focused on examining the email, evaluating the attached file in a sandbox environment, extracting indicators of compromise (IOCs), and tracking the Command and Control (C2) server the malware tried to reach. The ultimate goal was to contain the threat and confirm the alert as a true positive.

## Skills Gained
- Investigating phishing emails involving Excel 4.0 macros.
- Expertise in utilizing sandbox environments (Any.Run) for file analysis.
- Identifying C2 server locations through log and network analysis.
- Hands-on experience with log management tools to detect malicious activities.
- Containment and mitigation of phishing-related cyber threats.

## Tools Utilized
- **LetsDefend**:
  - **Log Management** for investigating and analyzing C2 addresses.
  - **Endpoint Security** to identify and isolate affected systems.
  - **Monitoring** and **Case Management** for tracking alerts and response actions.
- **External Tools**:
  - **VirusTotal** for evaluating file hashes and determining file safety.
  - **Any.Run** for sandboxing and conducting dynamic analysis of the suspicious file.
  - **Abuse IPDB** and **URLScan** for investigating associated IP addresses and URLs.

## Process

### 1. Investigating the Phishing Email
A **high-severity phishing alert** was triggered. The first step was to locate the email by searching for its subject.

  ![image](https://github.com/user-attachments/assets/30f94208-0d23-48cd-9ec0-c38743eee04b)


- **Attachment Found**: I unzipped the attachment in a **sandbox environment** and calculated the **MD5 hash values** for the extracted files.

![image](https://github.com/user-attachments/assets/92bce36f-4ee3-4862-8d9e-89432e895d39)


### 2. Analyzing the File Hashes
After unzipping, I found three distinct files. Each file's **hash** was analyzed using **VirusTotal**.

- **VirusTotal Results**: All the files were flagged as **malicious** by multiple security vendors.

![image](https://github.com/user-attachments/assets/b3e79c2c-6ef8-41ff-ab11-bec9ec6efd45)

![image](https://github.com/user-attachments/assets/554f59f0-0432-47d2-8c9a-dd163be47555)

  ![image](https://github.com/user-attachments/assets/1d494a70-1022-489a-a5cc-58adf2d78caa)

  
### 3. Tracking C2 Addresses
To identify the **C2 addresses** the malware attempts to connect with, I executed the malicious file in a **sandbox environment** via **Any.Run**.

- **C2 Addresses**: The IP addresses that the malware tries to contact were successfully identified.

![image](https://github.com/user-attachments/assets/75186173-22f9-4722-82cf-1714d4571c23)


### 4. Log Management and Further Investigation
I turned to **Log Management** to verify whether the **C2 addresses** had been accessed.

- **Log Findings**: The logs confirmed that the C2 addresses were accessed by the malware.

   ![image](https://github.com/user-attachments/assets/33538251-4585-4b11-a042-4b41cbb04e61)


### 5. Containment and Remediation
Once the malicious activity was confirmed, I initiated the **containment** process for the infected device.

- **Containment**: The device **LarsPRD** was isolated, and the malicious email was removed from Lars' inbox.

![image](https://github.com/user-attachments/assets/69b9112a-cbd8-4cdb-9926-aa479a6532a6)


### 6. Closing the Alert
After completing the analysis and containment steps, I closed the alert and marked it as a **True Positive**.

### Results:
- The phishing email was successfully identified.
- The attached Excel macro was confirmed to be malicious.
- The C2 addresses were tracked, and the malware was found to execute commands on the compromised system.
- The infected device was isolated, and the phishing email was deleted to prevent further harm.

   ![image](https://github.com/user-attachments/assets/462f0576-9ed9-4b1f-8f9c-e0a2538ff0b1)


## Conclusion
This project provided practical experience in detecting phishing attempts, sandboxing files, tracking C2 servers, and performing incident response. The use of **log management** and **endpoint security** tools allowed for effective monitoring and remediation, preventing further damage from the attack.
