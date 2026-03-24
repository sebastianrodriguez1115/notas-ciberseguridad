# Network Analysis Workflow

1.  Ingest Traffic  
    Once we have decided on our placement, begin capturing traffic. Utilize capture filters if we already have an idea of what we are looking for.

<!-- -->

2.  Reduce Noise by Filtering  
    Capturing traffic of a link, especially one in a production environment, can be extremely noisy. Once we complete the initial capture, an attempt to filter out unnecessary traffic from our view can make analysis easier. (Broadcast and Multicast traffic, for example.)

<!-- -->

3.  Analyze and Explore  
    Now is the time to start carving out data pertinent to the issue we are chasing down. Look at specific hosts, protocols, even things as specific as flags set in the TCP header. The following questions will help us:

Is the traffic encrypted or plain text? Should it be?

Can we see users attempting to access resources to which they should not have access?

Are different hosts talking to each other that typically do not?

1.  Detect the Root Issue  
    Are we seeing any errors? Is a device not responding that should be?

Use our analysis to decide if what we see is benign or potentially malicious.

Other tools like IDS and IPS can come in handy at this point. They can run heuristics and signatures against the traffic to determine if anything within is potentially malicious.

1.  Fix and Monitor  
    Fix and monitor is not a part of the loop but should be included in any workflow we perform. If we make a change or fix an issue, we should continue to monitor the source for a time to determine if the issue has been resolved.
