# Network Analysis

# Descriptive Analysis

Descriptive analysis is an essential step in any data analysis. It serves to describe a data set based on individual characteristics. It helps to detect possible errors in data collection and/or outliers in the data set.

1.  What is the issue?
    - Suspected breach? Networking issue?

<!-- -->

2.  Define our scope and the goal. (what are we looking for? which time period?)
    - Target: multiple hosts potentially downloading a malicious file from bad.example.com

    <!-- -->

    - When: within the last 48 hours + 2 hours from now.

    <!-- -->

    - Supporting info: filenames/types 'superbad.exe' 'new-crypto-miner.exe'

<!-- -->

3.  Define our target(s) (net / host(s) / protocol)
    - Scope: 192.168.100.0/24 network, protocols used were HTTP and FTP.

Using our workflow, we will determine our issue, what we are looking for, when, and where to find it. Descriptive analysis covers these critical concepts for our analysis.

# Diagnostic Analysis

Diagnostic analysis clarifies the causes, effects, and interactions of conditions. In doing so, it provides insights that are obtained through correlations and interpretation. Characteristic here is a backward-looking view, as in the closely related descriptive analytics, with the subtle difference that it tries to find reasons for events and developments.

4.  Capture network traffic
    - Plug into a link with access to the 192.168.100.0/24 network to capture live traffic to try and grab one of the executables in transfer. See if an admin can pull PCAP and/or netflow data from our SIEM for the historical data.

<!-- -->

5.  Identification of required network traffic components (filtering)
    - Once we have traffic, filter out any packets not needed for this investigation to include; any traffic that matches our common baseline and keep anything relevant to the scope of the investigation. For example, HTTP and FTP from the subnet, anything transferring or containing a GET request for the suspected executable files.

<!-- -->

6.  An understanding of captured network traffic
    - Once we have filtered out the noise, it is time to dig for our targets—filter on things like ftp-data to find any files transferred and reconstruct them. For HTTP, we can filter on http.request.method == "GET" to see any GET requests that match the filenames we are searching for. This can show us who has acquired the files and potentially other transfers internal to the network on the same protocols.

By capturing traffic around the source of our issue, clearing out any known good data, and then taking the time to inspect and understand what is left, we can determine if it is the cause of our problem. In doing so, we just performed diagnostic analysis. We are validating the cause of our problems and examining the events surrounding them.

# Predictive Analysis

By evaluating historical and current data, predictive analysis creates a predictive model for future probabilities. Based on the results of descriptive and diagnostic analyses, this method of data analysis makes it possible to identify trends, detect deviations from expected values at an early stage, and predict future occurrences as accurately as possible.

7.  Note-taking and mind mapping of the found results
    - Annotating everything we do, see, or find throughout the investigation is crucial. Ensure we are taking ample notes, including:

    <!-- -->

    - Timeframes we captured traffic during.

    <!-- -->

    - Suspicious hosts within the network.

    <!-- -->

    - Conversations containing the files in question. ( to include timestamps and packet numbers)

<!-- -->

8.  Summary of the analysis (what did we find?)
    1.  Finally, summarize what we have found explaining the relevant details so that superiors can decide to quarantine the affected hosts or perform more significant incident response.

    <!-- -->

    2.  Our analysis will affect decisions made, so it is essential to be as clear and concise as possible.

By performing an evaluation of the data we have found, comparing it to our baseline traffic, and known bad data such as markers of infiltration or exploitation (like signatures for viruses and other hacking tools), we are performing Predictive Analysis. In this process, we paint a clear picture so that appropriate actions can be taken in response.

# Prescriptive Analysis

Prescriptive analysis aims to narrow down what actions to take to eliminate or prevent a future problem or trigger a specific activity or process. Using the results of our workflow, we can make sound decisions as to what actions are required to solve the problem and prevent it from happening again. To prescribe a solution is the culmination of this workflow. Once done and the problem is solved, it is prudent to reflect on the entire process and develop lessons learned. These lessons, when documented, will enable us to make our processes stronger—document what was done correctly, what actions failed to help, and what could improve.  
  
This workflow is an example of how to begin the analysis process on captured traffic. Above we broke it down into its parts to explain where they fit within the analysis process and with which type of analysis it belongs. We include it here again as a whole so that it can serve as a template.

1.  What is the issue?
    1.  Suspected breach? Networking issue?

<!-- -->

2.  Define our scope and the goal (what are we looking for? which time period?)
    1.  target: multiple hosts potentially downloading a malicious file from bad.example.com

    <!-- -->

    2.  when: within the last 48 hours + 2 hours from now.

    <!-- -->

    3.  supporting info: filenames/types 'superbad.exe' 'new-crypto-miner.exe'

<!-- -->

3.  Define our target(s) (net / host(s) / protocol)
    1.  scope: 192.168.100.0/24 network protocols used were HTTP and FTP.

<!-- -->

4.  Capture network traffic
    1.  plug into a link with access to the 192.168.100.0/24 network to capture live traffic to try and grab one of the executables in transfer. See if an admin can pull PCAP and/or netflow data from our SIEM for the historical data.

<!-- -->

5.  Identification of required network traffic components (filtering)
    1.  once we have traffic, filter out any traffic not needed for this investigation to include; any traffic that matches our common baseline and keep anything relevant to the scope. \`HTTP and FTP from the subnet, anything transferring or containing a GET request for the suspected executable files.

<!-- -->

6.  An understanding of captured network traffic
    1.  Once we have filtered out the noise, it's time to dig for our targets—filter on things like ftp-data to find any files transferred and reconstruct them. For HTTP, we can filter on http.request.method == "GET" to see any GET requests that match the filenames we are searching for. This can show us who has acquired the files and potential other transfers internal to the network on the same protocols.

<!-- -->

7.  Note-taking and mind mapping of the found results.
    1.  Annotating everything we do, see, or find throughout the investigation is crucial. Ensure we are taking ample notes, including:
        1.  Timeframes we captured traffic during.

        <!-- -->

        2.  Suspicious hosts within the network.

        <!-- -->

        3.  Conversations containing the files in question. ( to include timestamps and packet numbers)

<!-- -->

8.  Summary of the analysis (what did we find?)
    1.  Finally, summarize what has been found, explaining the relevant details so that superiors can make an informed decision to quarantine the affected hosts or perform more significant incident response.

    <!-- -->

    2.  Our analysis will affect decisions made, so it is essential to be as clear and concise as possible.

Often this process is not a once-and-done kind of thing. It is usually cyclic, and we will need to rerun steps based on our analysis of the original capture to build a bigger picture. This could have been a much larger attack than what is in the examples. Suppose a full-scale incident response is deemed necessary. In that case, we may have to reanalyze the PCAP previously captured to look at any conversations that involve the affected hosts within several minutes of the executable transfer to ensure it did not spread over another route, as an example.
