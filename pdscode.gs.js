// Function to create the add-on card
function getContextualAddOn(e) {
  var card = CardService.newCardBuilder();
  
  // Header section
  var header = CardService.newCardHeader()
    .setTitle("Phishing Link Detector")
    .setSubtitle("Scans for suspicious links")
    
  card.setHeader(header);

  // Section with text and button
  var section = CardService.newCardSection();

  // Text paragraph widget
  var textWidget = CardService.newTextParagraph().setText("Click 'Scan' to analyze links for phishing threats.");
  section.addWidget(textWidget);

  // Button widget
  var button = CardService.newTextButton()
    .setText("SCAN")
    .setOnClickAction(CardService.newAction().setFunctionName("scanForPhishingLinks"));
  section.addWidget(CardService.newButtonSet().addButton(button));

  // Add section to the card
  card.addSection(section);

  return card.build();
}
// Function to scan emails for potential phishing links
// Function to scan the currently opened email for potential phishing links
function scanForPhishingLinks(e) {
  var accessToken = e.gmail.accessToken; // Get access token 
  GmailApp.setCurrentMessageAccessToken(accessToken); // Set token for the current Gmail message
  var message = GmailApp.getMessageById(e.gmail.messageId); // Get the message using messageId
  var phishingLinks = [];
  var body = message.getBody(); // Extract the body of the email
  var urls = body.match(/https?:\/\/[^\s]+/g); // Extract all URLs from the body
  if (urls) {
    urls.forEach(function(url) {
      if (typeof url === 'string' && isSuspiciousUrl(url)) {
        phishingLinks.push(url); // Add suspicious URLs to the list
      }
    });
  }
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification()
    .setText(phishingLinks.length > 0 ? 'WARNING!!! SUSPICIOUS LINKS FOUND: ' + phishingLinks.join(', ') : 'No suspicious links found.'))
    .build();
}

// Function to check if the URL is suspicious
function isSuspiciousUrl(url) {
  var suspiciousPatterns = [
  // Misspelled or lookalike domains
  'goog1e.com', 'g00gle.com', 'googlee.com', 'g00g1e.com', 'pay-pal.com', 'faceb00k.com', 'micros0ft.com', 'amaz0n.com', 'bank0famerica.com', 'y0utube.com', 'netf1ix.com', 'chase-secure.com', 'ver1zon.com',
  
  // Phishing-specific domains
  'login-fake.com', 'bankofamerica-fraud.com', 'appleid-login.net', 'paypal-update.com', 'amazon-authenticate.com', 'secure-login-bankofamerica.com', 'verify-your-account.net', 'secure-accounts-update.com', 'update-your-info-now.com',
  
  // Suspicious TLDs
  '.ru', '.cn', '.tk', '.ml', '.cf', '.ga', '.gq', '.info', '.xyz', '.click', '.link', '.biz', '.pw', '.top', '.win', '.icu', '.men', '.stream', '.zip', '.gdn', '.party', '.work', '.buzz',
  
  // Shortened URLs
  'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly', 'bit.do', 'tiny.cc', 'tr.im', 'adf.ly', 'j.mp',
  
  // Suspicious subdomains and redirections
  'login.yourbank.com', 'support.google.com', 'paypal.com.security-warning.com', 'verification.bankofamerica.example.com', 'secure-login.microsoft.com', 'account-update.amazon.com',
  
  // URL encoding
  '%20', '%2F', '@', '192.168.', '%3A', '%3F', '%3D', '%2B', '%2A', '%7E', '%21', '%23', '%24', '%25', '%26', '%27', '%28', '%29', '%2C', '%2E', '%2F', '%3A', '%3B', '%3C', '%3E', '%3F', '%40', '%5B', '%5D', '%7B', '%7D',
  
  // Uncommon ports
  ':8080', ':8443', ':3000', ':5000', ':6666', ':8888', ':21', ':22', ':25', ':110', ':143', ':993', ':995'
];


  for (var i = 0; i < suspiciousPatterns.length; i++) {
    if (url.indexOf(suspiciousPatterns[i]) !== -1) { // Use indexOf for compatibility
      return true;
    }
  }
  return false;
}
// Create the onOpen trigger (set the add-on available in Gmail)
function onGmailMessageOpen(e) {
  return getContextualAddOn(e);
}
function doGet(){
return HtmlService.createHtmlOutputFromFile('Index'); 
}
