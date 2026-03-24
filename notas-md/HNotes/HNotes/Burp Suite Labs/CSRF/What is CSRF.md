# What is CSRF?

CSRF stands for Cross-Site Request Forgery. It is a type of web security vulnerability that allows an attacker to trick a user into performing unwanted actions on a web application where they are currently authenticated.

In a CSRF attack, the malicious actor exploits the trust that a website has in the user's browser. Here's how it typically works:

- The user is logged into a legitimate website (e.g., a bank)

<!-- -->

- The user then visits a malicious website or clicks a malicious link

<!-- -->

- This malicious site contains code that sends a request to the legitimate site

<!-- -->

- The legitimate site sees the request coming from the user's browser with their session cookie and processes it

CSRF attacks can lead to unauthorized actions being performed on behalf of the authenticated user, such as changing account details, making purchases, or transferring funds.

In order for a CSRF attack to be possible:

- A relevant action, for example change users email

<!-- -->

- Cookie-based session handling

<!-- -->

- No unpredictable request parameters
