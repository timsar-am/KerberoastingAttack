# PROJECTNAME

Investigating a Kerberoasting Attack 

## Objective

Scenario: As a diligent Cyber threat hunter, your investigation begins with a hypothesis: 'Recent trends suggest an upsurge in Kerberoasting attacks within the industry. Could your organization be a potential target for this attack technique?' This hypothesis lays the foundation for your comprehensive investigation, starting with an in-depth analysis of the domain controller logs to detect and mitigate any potential threats to the security landscape.

Note: Your Domain Controller is configured to audit Kerberos Service Ticket Operations, which is necessary to investigate Kerberoasting attacks. Additionally, Sysmon is installed for enhanced monitoring

### Skills Learned

- Threat Hunting
- Network Forensics 

### Tactics

- Credential Access
- Discovery

### Tools Used

- Splunk

## Steps

Question: To mitigate Kerberoasting attacks effectively, we need to strengthen the encryption Kerberos protocol uses. What encryption type is currently in use within the network? 

First thing I do is look for event ID 4769. This event occurs when a service ticket has been requested. 

![image](https://github.com/user-attachments/assets/897cb57e-e19a-47ed-9854-5106bb914469)

![image](https://github.com/user-attachments/assets/3d6649ac-de41-4c2a-94ff-9656be2f763f)

We can see here information about the encryption type. A quick search leads me to the Microsoft website where I find what 0x17 is named. RC4-HMAC

![image](https://github.com/user-attachments/assets/8117bd9f-b259-49b8-bfac-2a9baa366388)

Question: What is the username of the account that sequentially requested Ticket Granting Service (TGS) for two distinct application services within a short time frame? 

I add the below fields to focus on the users and services that the users requested TGS for. 
The administrator account only requested TGS for service DC01$. Next I look at events related to johndoe. 

![image](https://github.com/user-attachments/assets/ce89e1f5-2eb0-4e76-ae7e-17ce99251b7f)

I run the following search and pipe to table to get an understanding of his timeline.

![image](https://github.com/user-attachments/assets/7a2dd7f6-e2d4-4f4e-b190-899b35a053bf)

Here we can see johndoe and the pattern for requesting TGS. The answer is johndoe.

![image](https://github.com/user-attachments/assets/b952e118-9330-42b0-90ec-1df474a71adc)

Question: Based on the previous question, we know that johndoe requested TGS for SQLService which suggests this service was targeted. This would be an attractive target for an attacker as if they gain access to SQL Server’s service account, they gain control of the databases on that server. Answer is SQLService.

I search for Event ID 4624 (successful logon) and the user we already know of johndoe.

![image](https://github.com/user-attachments/assets/3b95e73a-0ea7-42a5-9225-794ecfa874a5)

Only 1 IP address is associated with logons from johndoe. 10.0.0.154

![image](https://github.com/user-attachments/assets/a32aeab6-0112-4818-a53c-5fc78748efa8)

Question: To understand the attacker's actions following the login with the compromised service account, can you specify the service name installed on the Domain Controller (DC)? 

Event ID for service installation is 4697. I run a search for this event. No event shows up. I search for Event ID 7045 (New Service Installed) I get 2 events.

![image](https://github.com/user-attachments/assets/81a59f71-f211-4b91-ac08-aea9cb192397)

I look at which service was installed first. Answer is iOOEDsXjWeGRAyGl

![image](https://github.com/user-attachments/assets/5f978c11-f50d-4f03-98e8-d9c2b91b59b3)

Question: To grasp the extent of the attacker's intentions, What's the complete registry key path where the attacker modified the value to enable Remote Desktop Protocol (RDP)? 

I search for Event ID 4657 associated with registry key being modified. No event comes up. I do some digging on the Splunk website. And find this:

![image](https://github.com/user-attachments/assets/dad672d6-b36e-4b8a-9369-0e3f508392e9)

I look for event code 13. 707 Events.

![image](https://github.com/user-attachments/assets/ff452163-dbd3-4914-a582-04ce0eaf6e0f)

I do more research and learn:

Registry changes related to Remote Desktop Protocol (RDP) include: 
    • fDenyTSConnections key 
      The value of this key determines whether RDP is enabled or disabled: 
    • 0: RDP is enabled
    • 1: RDP is disabled 
I run another search including fDenyTSConnections. Narrowed down to one event. 

![image](https://github.com/user-attachments/assets/7ea32191-6d6d-47fc-8d31-9da8c9c3cfcd)

A look through the event I find the answer.  HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections

![image](https://github.com/user-attachments/assets/a6f8c3b8-8d5d-4f31-ba08-d314a837f4f0)

Question: To create a comprehensive timeline of the attack, what is the UTC timestamp of the first recorded Remote Desktop Protocol (RDP) login event? 
I need to look for Event ID 4624 (successful logon) with logon type 10.  I will also sort it by _time to get an understanding of the first event. Two events show up. The Answer is 2023-10-16 07:50

![image](https://github.com/user-attachments/assets/7742e645-0ea1-4f9b-9241-9b42386ed926)

Question: To unravel the persistence mechanism employed by the attacker, What is the name of the WMI event consumer responsible for maintaining persistence?
I do some digging and learn Sysmon event ID 20 logs registration of WMI consumers. The attacker will typically craft a consumer that blends in with legitimate system processes. I add the field winlogevent_data.Name

![image](https://github.com/user-attachments/assets/3ca2e53e-1084-4156-be37-874a18e07064)

I find the event and the answer is Updater. Made to look like a legitimate process. 

![image](https://github.com/user-attachments/assets/c09c74ab-ae0a-4437-afaf-514eda7e6b43)

Question: Which class does the WMI event subscription filter target in the WMI Event Subscription you've identified?
I had to do some digging on this. WMI filters can be used to apply Group Policy Objects. These filters can be used to apply GPO to machines based on certain settings enabled, particular program installed or with an IP subnet. Event ID 19 is associated with WMI filter activity.  I run the search.

![image](https://github.com/user-attachments/assets/ec24a610-87d5-4b53-8f4e-dcce333ca6e3)

Only 1 Event shows up. I look through the event for the answer. I see the script attacker ran and the answer to the question. Win32_NTLogEvent

![image](https://github.com/user-attachments/assets/599ee3ce-1f10-4c34-80a2-70d3c1ed80b2)
