# SOC-Automation-Lab

### **Architecture**

#### Logical Diagram

<img width="556" alt="Screenshot 2025-04-30 at 1 11 09 PM" src="https://github.com/user-attachments/assets/b8789b43-ff4b-4475-984e-27491c5b597d" />


The setup consists of the following main components:

1. **Wazuh Manager (Azure Cloud VM - Ubuntu 22.04)**:
    
    - Acts as the central monitoring and management server for receiving, analyzing, and respo.      nding to security events.
        
2. **Wazuh Agent (Azure Cloud VM - Windows 10)**:
    
    - Installed on a Windows 10 virtual machine to collect and forward security data to the Wazuh Manager.
        
3. **TheHive (Local VM - Ubuntu 22.04)**:
    
    - Used for threat analysis and incident response. It is hosted on a local Ubuntu VM.
        
4. **Shuffle (Cloud)**:
    
    - An automation and orchestration tool integrated with both Wazuh and TheHive.
        
    - Automates workflows to streamline alert management and incident response.

    ![Wazuh Automation drawio](https://github.com/user-attachments/assets/ca6fd0d0-b220-4158-9a84-1403c095f21d)


5. **SOC Analyst (Local/Remote Workstation)**:
    
    - Responsible for monitoring alerts and incidents through TheHive and Shuffle.
        

#### **Data Flow:**

1. **Wazuh Agent → Wazuh Manager:** Sends security event data.
    
2. **Wazuh Manager → Shuffle:** Forwards alerts for enrichment.
    
3. **Shuffle → TheHive:** Creates alerts and incidents for investigation.
    
4. **Shuffle → VirusTotal:** Enriches data with threat intelligence.
    
5. **SOC Analyst → TheHive:** Investigates and analyzes alerts.
    
6. **Shuffle → SOC Analyst:** Sends notifications and response actions.
    
7. **Shuffle → Wazuh Manager:** Initiates response actions (e.g., block IP).

### **Setup**

#### **Network Configuration:**

 - Both Wazuh Manager and Wazuh Agent are deploye d on separate Azure VMs with different NSG group.

<img width="1440" alt="Azure VM's" src="https://github.com/user-attachments/assets/4cbdd9e0-57ff-4e62-8ceb-84e202a5c65f" />


- Shuffle is hosted in the cloud, while TheHive is running on a local VM with a static IP configuration.
    
- Necessary ports (1514, 1515, 55000) are opened on the Azure VMs through inbound and outbound rules for communication between the agent and manager.

	<img width="1440" alt="Wazuh-Manager-NSG" src="https://github.com/user-attachments/assets/7687212d-9e5f-430d-9834-d2828855c90c" />


	<img width="1440" alt="Wazuh-Agent-NSG" src="https://github.com/user-attachments/assets/65421134-ca16-48de-8db3-b06820ec062b" />


- The local Ubuntu VM running TheHive is configured with a static IP to maintain consistent connectivity.
    

#### **Installation Process:**

1. **Wazuh Manager Installation:**
    
    - Deployed on an Azure VM (Ubuntu 22.04) using the official Wazuh installation script.
        
    - Configured to receive data from the Wazuh Agent.
        
2. **Wazuh Agent Installation:**
    
    - Deployed on a Windows 10 VM on Azure.
        
    - Manually configured to point to the Wazuh Manager IP address.
        
3. **TheHive Installation:**
    - Installed on a local Ubuntu VM using the automated script from TheHive’s official repository.
        
    - Configured with a static IP to ensure constant connectivity.
        
4. **Shuffle Installation and Configuration:**
    
    - Hosted on the cloud with necessary integrations configured for Wazuh and TheHive.
        
    - Configured to trigger workflows based on incoming Wazuh alerts.
        

#### **Workflow Configuration:**

- The integration between Wazuh, Shuffle, and TheHive was configured to automate the incident response process.
    
- Wazuh alerts trigger Shuffle workflows that enrich data with VirusTotal and forward it to TheHive.
    
- The SOC Analyst receives alert notifications and can perform responsive actions via Shuffle.

### **Installation and Configuration**

#### **1. Wazuh Manager Installation (Azure Ubuntu VM)**

##### **Prerequisites:**

- Azure account with VM creation permissions.
    
- Ubuntu 22.04 VM with at least 4 vCPUs, 16 GB RAM, and 45 GB disk space.
    
- Open necessary ports: **1514/UDP**, **1515/TCP**, **55000/TCP**.
    

##### **Steps:**

1. **Update the system:**
    
    ```bash
    sudo apt update && sudo apt upgrade -y
    ```
    
2. **Install Wazuh Manager using the official script:**
    
    ```bash
    curl -s https://packages.wazuh.com/4.x/wazuh-install.sh | sudo bash -s -- -m
    ```
    
3. **Check service status:**
    
    ```bash
    sudo systemctl status wazuh-manager
    ```
    
4. **Configure Firewall (if applicable):**
    
    ```bash
    sudo ufw allow 1514/udp
    sudo ufw allow 1515/tcp
    sudo ufw allow 55000/tcp
    sudo ufw enable
    ```
    
5. **Access Wazuh web interface:**
    
    - Open the browser and navigate to:
        
        ```
        https://<Public_IP>:55000
        ```
        
6. **Create an API user (if not already created):**
    
    ```bash
    sudo /var/ossec/bin/wazuh-control enable
    sudo /var/ossec/bin/wazuh-api
    ```
    

---

#### **2. Wazuh Agent Installation (Azure Windows VM)**

##### **Prerequisites:**

- Windows 10 VM.
    
- Sysmon installed for advanced event monitoring.
    
- Open necessary ports as above.
    

##### **Steps:**

1. **Install the Wazuh Agent:**

	- Go to wazuh manager dashboard - Click on deploy new agent
	- Select system details according to your environment and in server address write IP Address of Wazuh manager.

<img width="1440" alt="Add-Win-Agent-1" src="https://github.com/user-attachments/assets/c94bf190-476e-4d83-abd1-492d2d46c5fc" />


- Run the script provided on Administrator powershell and start the agent

	<img width="1440" alt="Add-Win-Agent-2" src="https://github.com/user-attachments/assets/c2b3820f-c2da-4f88-bf8c-b95425bf1652" />


2. **Check Wazuh Agent status:**
    ```powershell
    sc query WazuhSvc
    ```

3. Go to wazuh dashboard and check if agent is added:

<img width="1440" alt="Wazuh Dashboard" src="https://github.com/user-attachments/assets/ec226751-61c9-42b8-94da-40df3ee5e1c8" />


4. **Configure Sysmon:**
    
    - Download Sysmon from Microsoft Sysinternals and We will use configuration file (Sysmon-modular)
        
    - Download sysmon:
      <img width="1412" alt="Sysmon-Download" src="https://github.com/user-attachments/assets/a04af5fc-f040-4db9-96dd-245d1c501613" />

        
	- Download configuration
		<img width="1292" alt="Sysmon-Config-Download" src="https://github.com/user-attachments/assets/73b37753-8414-46e1-802d-d1c36bab7ed5" />

		
	- Run sysmon using following command
        ```powershell
        .\sysmon -i sysmonconfig.xml
        ```

	- After running the command go to event viewer and check if it is installed properly.

	<img width="1440" alt="Check-Sysmon-Installed" src="https://github.com/user-attachments/assets/ac8cf8be-0c29-4610-93b1-cbc58b9c2c99" />

	

---

#### **3. TheHive Installation (Local Ubuntu VM via UTM on Mac)**

##### **Prerequisites:**

- UTM installed on Mac with Ubuntu 22.04 VM.
    
- Static IP configuration (optional if using localhost).
    
- Allocate at least 4 vCPUs and 16 GB RAM.
    

##### **Steps:**

     
1. **Configure Static IP (if needed):**
    
    ```bash
    sudo nano /etc/netplan/01-network-manager-all.yaml
    ```
    
    <img width="1440" alt="Thehive-install-static-ip" src="https://github.com/user-attachments/assets/5d71bfec-0109-403c-a28a-d92538993845" />

    - Add the static IP configuration and apply:
        
        ```bash
        sudo netplan apply
        ```
        

2. Install TheHive using the automated script: https://docs.strangebee.com/thehive/installation/automated-installation-script/

	<img width="1440" alt="Thehive-install-automatic-script" src="https://github.com/user-attachments/assets/22889db5-fb15-45de-9d42-bca404508ec4" />

	
    ```bash
    wget -q -O /tmp/install.sh https://archives.strangebee.com/scripts/install.sh
    sudo bash /tmp/install.sh
    ```
    
3. **Choose the installation option for TheHive (Option 2):**
    
    - Follow the prompts to complete the installation.

4. **Access TheHive:**
    
    - Open a browser:
        
        ```
        http://<TheHive_IP>:9000
        ```
	
	<img width="1440" alt="Thehive-login-page" src="https://github.com/user-attachments/assets/e49c8ae3-52af-4f9a-a754-1d587cf0bbd0" />


---

#### **4. Shuffle Installation (Cloud)**

##### **Steps:**

1. **Access Shuffle via browser:**
    
    - URL:
        
        ```
        https://app.shuffle.dev
        ```
        
2. **Log in and configure integrations:**
    
    - Integrate Wazuh and TheHive using API keys.
        
3. **Test the connection:**
    
    - Run a simple workflow to check the connectivity.
        

---

### **Troubleshooting**

#### **Common Issues and Fixes:**

1. **Agent not showing on Wazuh Dashboard:**
    
    - Check agent status:
        
        ```powershell
        sc query WazuhSvc
        ```
        
    - Restart if necessary:
        
        ```powershell
        net stop WazuhSvc
        net start WazuhSvc
        ```
        
    - Re-register the agent:
        
        ```bash
        /var/ossec/bin/agent-auth -m <Wazuh_Manager_IP>
        ```
        
    - Verify port accessibility using:
        
        ```bash
        telnet <Wazuh_Manager_IP> 1515
        ```
        
2. **Cannot ping Wazuh Manager:**
    
    - Verify that the NSG allows inbound ICMP traffic.
        
    - Check private IP connectivity if both VMs are in the same VNet.
        
3. **Shuffle Workflow Issues:**

    - Connect branches properly to avoid the error “not under start node”.
        
    - Double-check API keys and URLs in the workflow.
        
4. **Azure NSG Configuration Issues:**
    
    - Ensure both inbound and outbound rules are correctly configured for the required ports.
        
    - Avoid having conflicting rules (e.g., denying all inbound traffic).
        
5. **Wazuh Agent Not Starting:**
    
    - Check the logs:
        
        ```powershell
        Get-Content "C:\Program Files (x86)\ossec-agent\logs\ossec.log" -Tail 50
        ```
        
    - Reinstall if necessary:
        
        ```powershell
        msiexec /x C:\path\to\wazuh-agent.msi /quiet
        ```
        

---

### **Integration Workflow**

#### **Objective:**

Automate the detection, enrichment, and alerting process for potential security threats, specifically focusing on detecting Mimikatz-related events from Wazuh.

#### **Workflow Overview:**

The integration workflow leverages the following components:

1. **Wazuh (Alerts)**: Detects Mimikatz usage and sends an alert to Shuffle.
    
2. **Shuffle**:
    
    - Extracts the SHA256 hash from the Mimikatz alert.
        
    - Sends the extracted hash to VirusTotal for threat intelligence.
        
    - Integrates with TheHive to generate a case or alert.
        
    - Sends an email notification to the SOC analyst with the VirusTotal report.
        
3. **VirusTotal**: Enriches the hash data by fetching a threat report.
    
4. **TheHive**: Displays the alert as a new case for further investigation.
    
5. **Email Notification**: Sends an alert email to the SOC analyst with the relevant hash details and VirusTotal report.
    

---

#### **Step-by-Step Workflow Execution:**

1. **Receiving Alerts from Wazuh:**

	- Copy the webhook uri

	<img width="1341" alt="Shuffle-webhook-copy-uri" src="https://github.com/user-attachments/assets/e7059e7d-9a0e-49a0-9594-10a8941c4d14" />


    - Edit the Wazuh server configuration file `/var/ossec/etc/ossec.conf` and add a configuration similar to the following with a Shuffle webhook URI:

```
<integration>
  <name>shuffle</name>
  <hook_url>http://<YOUR_SHUFFLE_URL>/api/v1/hooks/<HOOK_ID></hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

 - Wazuh continuously monitors the system for suspicious activities, including Mimikatz usage.
        
    - Once an alert is generated for Mimikatz, it is sent to Shuffle via the **Wazuh.Alerts** webhook node.
        
    - The alert data typically contains details such as the SHA256 hash, timestamp, and event description.
        
2. **Extracting the SHA256 Hash:**
    
    - Shuffle uses a **Regex Extraction Node** to parse the alert and extract the SHA256 hash.
    - As we get MD5,SHA1 and SHA256 hashes in the alert, we use regex to only extract SHA256 hash.
    - This step ensures that only relevant data (hash) is sent to the next stage.

    <img width="1349" alt="Shuffle-regex-configuration" src="https://github.com/user-attachments/assets/1e2a1b11-3ae6-4828-8ad3-3bbe8a7a6c86" />

        
3. **Sending Hash to VirusTotal:**
    
    - The extracted hash is sent to the **VirusTotal** API node within Shuffle.
        
    <img width="1351" alt="Shuffle-Virusotal-hash-report-argument" src="https://github.com/user-attachments/assets/a019d7b9-f186-412f-922a-699269ea1f81" />

        
    - VirusTotal queries its database for information about the hash, including reputation, file analysis, and previous detections.
        
    - Shuffle stores the results for subsequent processing.
        
4. **Generating an Alert on TheHive:**
    
    - Once the hash information is obtained, Shuffle uses the **TheHive** integration to create a new alert.
        
    - The alert contains the following details:

  <img width="1341" alt="Shuffle-TheHive-Alert-Argument" src="https://github.com/user-attachments/assets/3e853b05-df99-4e5b-8b63-a31d0c31216e" />

	<img width="1338" alt="Shuffle-TheHive-Alert-json-body" src="https://github.com/user-attachments/assets/886f916e-bc06-42b0-b14b-9ce2904d98a5" />


	The alert is displayed on TheHive dashboard for further investigation.
        
5. **Email Notification to SOC Analyst:**
    
    - Shuffle triggers the **Email** node to notify the SOC analyst.
        
    - The email contains:
    <img width="1343" alt="Shuffle-Email-Alert-Details" src="https://github.com/user-attachments/assets/6a47c029-36ac-4f93-a994-0397d192f3bf" />

        
    - This ensures timely notification and allows for rapid response.
        

---

#### **Troubleshooting Shuffle Workflow:**

- If the alert does not appear on TheHive:
    
    - Verify that TheHive API key is correctly configured in Shuffle.
		
	Since TheHive is running on my local VM and Shuffle is hosted on the cloud, I used **ngrok**to port forward the local VM's IP and port. This allowed me to point Shuffle to the IP and po rt of my local machine, enabling communication between the two.

	Download Ngrok:
	<img width="1440" alt="Ngrok-installation-document" src="https://github.com/user-attachments/assets/28238e81-a0a5-4901-99e9-e11532f01905" />


	Port forward Local Host IP to TheHive IP:
	<img width="1440" alt="Ngrok-port-forward-command" src="https://github.com/user-attachments/assets/925ac97d-b3fe-4b25-9345-3647fcc9557c" />


	Copy the Forwarded address and paste it in Shuffle TheHive Authentication url:
	<img width="1440" alt="Ngrok-to-Thehive-portforwarding" src="https://github.com/user-attachments/assets/55d30b6e-560a-43db-8554-ef98a2c452ac" />


	Provide API key and TheHive url for TheHive Authentication on Shuffle:
	<img width="1440" alt="Shuffle-thehive-authentication-api" src="https://github.com/user-attachments/assets/7607752f-603e-4c94-aebb-7738549c2aed" />




- Check that the node is correctly connected in the Shuffle workflow.
        
- VirusTotal hash check fails:
    
    - Ensure the API key is correctly set and valid.
        
    - Verify that the SHA256 format is correctly extracted and passed.
        
- Email not sent:
    
    - Check the SMTP settings in the Shuffle configuration.
        
    - Verify that the email node is correctly connected to the final step of the workflow.
        

---

### **Testing and Validation**

#### **Objective:**

To ensure the proper functioning of the integrated SOC automation workflow, including accurate detection, data enrichment, alert generation, and analyst notification.

---

#### **Validation and Results:**

##### **1. Alert Generation and Transmission:**

- Successfully generated a Mimikatz alert from the Windows Wazuh agent.
    
- Wazuh manager captured the alert and forwarded it to Shuffle.
    
- Verification:
    
    - Check Wazuh logs and alert files to confirm alert generation.
        
    - Ensure the webhook node in Shuffle successfully received the alert data.
        
	<img width="1440" alt="Shuffle-alert-usage-detected" src="https://github.com/user-attachments/assets/8e6f2d97-0976-4796-94ec-1825de2c52ad" />
        

##### **2. Alert Processing in Shuffle:**

- Shuffle received the alert and extracted the SHA256 hash successfully.
    
- The extracted hash was accurately sent to VirusTotal for enrichment.
    
- Verification:
    
    - Monitor Shuffle logs for hash extraction and VirusTotal query.
        
	
      <img width="1364" alt="Shuffle-sha256-regex-result" src="https://github.com/user-attachments/assets/e2efd6ba-454b-42b3-976b-c02cc58d3989" />


##### **3. VirusTotal Hash Report:**

- VirusTotal returned threat intelligence data for the given hash.
    
- The data was forwarded to TheHive for alert creation.
    
- Verification:
    
    - Check VirusTotal logs in Shuffle.
        
    - Validate the response contains the hash reputation and threat details.
        
    <img width="1363" alt="Shuffle-Virustotal-Result-report" src="https://github.com/user-attachments/assets/6883b2c5-0354-4db3-b32c-8ef48b145c19" />

        

##### **4. Alert Creation on TheHive:**

- The alert was successfully created in TheHive with enriched data from VirusTotal.
    
- All relevant fields were correctly populated (e.g., hash, description, threat score).
    
- Verification:
    
    - Open TheHive dashboard and view the alert.
        
    - Validate the alert fields and content.
        
    <img width="1353" alt="Shuffle-TheHive-result" src="https://github.com/user-attachments/assets/51d13be9-47c6-4ec7-9e63-f12e90ad2cd6" />

        

##### **5. Email Notification to Analyst:**

- The SOC analyst received an email notification about the newly created alert.
    
- The email included hash details and a summary of the VirusTotal report.
    
- Verification:
    
    - Check the email inbox for the notification.
    <img width="1440" alt="Shuffle-squarex-alert-email-notification" src="https://github.com/user-attachments/assets/a2e16262-521f-48b7-a579-9fcd7f1c077a" />

    
    - Verify that the contents match the expected format. 
    <img width="1440" alt="Shuffle-squarex-alert-email-details" src="https://github.com/user-attachments/assets/2446ff2c-3a13-443b-86c9-51a011d2bd5b" />


---

### **Lessons Learned and Improvements**

#### **Lessons Learned:**

1. **Integration Challenges:**
    
    - Setting up Wazuh, TheHive, and Shuffle on separate environments (local VM, cloud VMs) presented networking and connectivity challenges. Proper configuration of firewalls, IP addresses, and port forwarding was essential. 
        
2. **API Configuration Issues:**
    
    - Since TheHive is running on my local VM and Shuffle is hosted on the cloud, I used **ngrok**to port forward the local VM's IP and port. This allowed me to point Shuffle to the IP and port of my local machine, enabling communication between the two.
    
3. **Workflow Execution Issues:**
    
    - Understanding Shuffle’s start node logic was crucial. The absence of a correctly configured start node caused the entire workflow to fail. Setting Wazuh alerts as the start node resolved this problem.
        
4. Cross-Cloud Integration:
    
    - Connecting Wazuh on Azure and Shuffle in the cloud required careful consideration of public and private IPs. Ensuring the Wazuh manager was accessible from the Shuffle instance was key.
        

---

#### **Improvements:**

1. **Enhanced Documentation:**
    
    - Creating clear, step-by-step documentation from the start would have reduced time spent troubleshooting issues related to API integration and node configuration.
        
2. Optimized Workflow Structure:
    
    - Reviewing Shuffle’s documentation more thoroughly before starting the project could have minimized errors related to setting up nodes and running workflows.


### **Conclusion**

This project successfully demonstrated the integration of Wazuh, TheHive, and Shuffle to automate SOC workflows. By leveraging cloud and local environments, we established a robust alerting and response system capable of detecting threats and enriching them with VirusTotal data. Despite challenges related to API configuration, networking, and workflow design, the integration proved effective after troubleshooting and optimization. This setup provides a scalable and efficient approach for automating SOC operations, enhancing threat detection, and streamlining response processes.


Refrences for the project:

1. Wazuh Installation Document:
[https://documentation.wazuh.com/current/installation-guide/wazuh-server/installation-assistant.html**](https://documentation.wazuh.com/current/installation-guide/wazuh-server/installation-assistant.html)

2. Integrating Wazuh with shuffle API Documentation:
[https://wazuh.com/blog/integrating-wazuh-with-shuffle/](https://wazuh.com/blog/integrating-wazuh-with-shuffle/)

3. Sysmon Download:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

4. Sysmon Config:
https://github.com/olafhartong/sysmon-modular

5. TheHive Installation Document:
https://docs.strangebee.com/thehive/installation/automated-installation-script/

6. TheHive API Documentation:
https://docs.strangebee.com/thehive/api-docs/

7. UTM Virtual Machine Download:
https://mac.getutm.app

8. Shuffle for workflow automation:
https://shuffler.io

9. SqaureX for receiving email alert:
https://sqrx.com

10. Source of project learning from youtube channel MyDFIR:
[www.youtube.com/@MyDFIR](http://www.youtube.com/@MyDFIR)
