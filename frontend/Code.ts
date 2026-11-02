const BACKEND_ANALYZE_URL = 'https://grill-jiffy-wriggly.ngrok-free.dev/api/analyze';

function onGmailMessageOpen(e) {
    // Get access data from the email open event
    const messageId = e.gmail.messageId;
    const accessToken = e.gmail.accessToken;
    
    // Set temporary permission to fetch the specific email content
    //GmailApp.setCurrentMessageAccessToken(accessToken);
    const message = GmailApp.getMessageById(messageId);
    
    // Extract data
    const sender = message.getFrom();
    const subject = message.getSubject();
    const body = message.getBody();
    
    // Extract raw content to parse hidden authentication headers 
    const rawContent = message.getRawContent();
    const authHeaderMatch = rawContent.match(/^Authentication-Results:\s*([\s\S]*?)(?=\r?\n[a-zA-Z0-9\-]+:)/im);
    const authResults = authHeaderMatch ? authHeaderMatch[1].trim().toLowerCase() : '';
    
    // Check if the sender is already known
    const isKnownSender = checkIfKnownSender(sender);
    
    // Send to Backend
    let score = 0;
    let verdict = 'Error';
    let reasoning = ['Could not analyze email.'];
    let color = '#EA4335'; 

    try {
        const response = UrlFetchApp.fetch(BACKEND_ANALYZE_URL, {
            method: 'post',
            contentType: 'application/json',
            payload: JSON.stringify({ sender, subject, body, isKnownSender, authResults }),
            muteHttpExceptions: true
        });
        
        if (response.getResponseCode() === 200) {
            const data = JSON.parse(response.getContentText());
            score = data.score;
            verdict = data.verdict;
            reasoning = data.reasoning;
            color = data.color || color; 
            
            //apply risk label if score is 45 or higher
            if (score >= 45) {
                applyRiskLabel(message.getThread(), score);
            }
            
            // If the sender is not known and the score is below 40, save the sender as known
            if (!isKnownSender && score < 40) {
                saveSenderAsKnown(sender);
            }
            
        } else {
            reasoning = [`Server returned error code: ${response.getResponseCode()}`];
        }
    } catch (error) {
        reasoning = [String(error)];
    }

    // Build the Add-on UI
    return buildResultsCard(score, verdict, reasoning, color, sender, subject);
}

//function to apply risk label to the email thread based on the score
function applyRiskLabel(thread, score) {
    let labelName = null;
    if (score >= 70) {
        labelName = "Phishing Risk: High";
    } else if (score >= 45) {
        labelName = "Phishing Risk: Medium";
    }

    if (labelName) {
        let label = GmailApp.getUserLabelByName(labelName);
        if (!label) {
            label = GmailApp.createLabel(labelName);
        }
        thread.addLabel(label);
    }
}

function buildResultsCard(score, verdict, reasoning, color, sender, subject) {
    const card = CardService.newCardBuilder();
    
    const header = CardService.newCardHeader()
        .setTitle('Malicious Email Scorer')
        .setSubtitle(`Verdict: ${verdict}`);
    card.setHeader(header);
    
    const scoreSection = CardService.newCardSection()
        .setHeader('Threat Level');
        
    scoreSection.addWidget(CardService.newTextParagraph().setText(`<b>Score:</b> <font color="${color}">${score} / 100</font>`));
    
    //apply warning alert and button if score is 45 or higher
    if (score >= 45) {
        const alertSection = CardService.newCardSection();
        alertSection.addWidget(CardService.newTextParagraph().setText(`<b><font color="${color}">⚠️ Warning: This message has been flagged as high risk.</font></b>`));
        
        const ackAction = CardService.newAction().setFunctionName('acknowledgeWarning');
        const ackButton = CardService.newTextButton()
            .setText('I acknowledge the warning')
            .setBackgroundColor(color)
            .setOnClickAction(ackAction);
            
        alertSection.addWidget(ackButton);
        card.addSection(alertSection);
    }
    
    const reasoningSection = CardService.newCardSection()
        .setHeader('Analysis Details');
        
    reasoning.forEach(reason => {
        reasoningSection.addWidget(CardService.newTextParagraph().setText(`• ${reason}`));
    });

    const feedbackSection = CardService.newCardSection()
        .setHeader('was this analysis helpful?');
    const safeAction = CardService.newAction()
        .setFunctionName('submitUserFeedback')
        .setParameters({
            sender: sender,
            subject: subject,
            originalScore: String(score),
            userFeedback: 'Safe'
        });
    const maliciousAction = CardService.newAction()
        .setFunctionName('submitUserFeedback')
        .setParameters({
            sender: sender,
            subject: subject,
            originalScore: String(score),
            userFeedback: 'Malicious'
        });
    feedbackSection.addWidget(
        CardService.newButtonSet()
            .addButton(CardService.newTextButton()
                .setText('✅ mark as safe')
                .setOnClickAction(safeAction))
            .addButton(CardService.newTextButton()
                .setText('🚨mark as malicious')
                .setOnClickAction(maliciousAction))
    );
    
    card.addSection(scoreSection);
    card.addSection(reasoningSection);
    card.addSection(feedbackSection);
    
    return [card.build()];
}

// the function that is called when the warning button is clicked and shows a toast message at the bottom of the screen
function acknowledgeWarning(e) {
    return CardService.newActionResponseBuilder()
        .setNotification(CardService.newNotification().setText("The warning has been acknowledged. Please exercise caution with links in this email."))
        .build();
}

function submitUserFeedback(e) {
    const parameters = e.parameters || {};
    const userFeedback = parameters.userFeedback;
    if (userFeedback !== 'Safe' && userFeedback !== 'Malicious') {
        return CardService.newActionResponseBuilder()
            .setNotification(CardService.newNotification().setText('Could not submit feedback: invalid selection.'))
            .build();
    }

    const feedbackUrl = BACKEND_ANALYZE_URL.replace(/\/api\/analyze$/, '/api/feedback');
    try {
        const response = UrlFetchApp.fetch(feedbackUrl, {
            method: 'post',
            contentType: 'application/json',
            payload: JSON.stringify({
                sender: parameters.sender || '',
                subject: parameters.subject || '',
                originalScore: Number(parameters.originalScore),
                userFeedback: userFeedback
            }),
            muteHttpExceptions: true
        });

        if (response.getResponseCode() >= 200 && response.getResponseCode() < 300) {
            return CardService.newActionResponseBuilder()
                .setNotification(CardService.newNotification().setText('Thank you for your feedback!'))
                .build();
        }

        return CardService.newActionResponseBuilder()
            .setNotification(CardService.newNotification().setText('Could not submit feedback. Please try again later.'))
            .build();
    } catch (error) {
        console.error(`Feedback submission failed: ${error}`);
        return CardService.newActionResponseBuilder()
            .setNotification(CardService.newNotification().setText('Could not submit feedback. Please try again later.'))
            .build();
    }
}

function checkIfKnownSender(sender) {
    const userProperties = PropertiesService.getUserProperties();
    const storedSenders = userProperties.getProperty('knownSenders');
    const knownSenders = storedSenders ? JSON.parse(storedSenders) : [];
    
    return knownSenders.includes(sender);
}

function saveSenderAsKnown(sender) {
    const userProperties = PropertiesService.getUserProperties();
    const storedSenders = userProperties.getProperty('knownSenders');
    const knownSenders = storedSenders ? JSON.parse(storedSenders) : [];
    
    if (!knownSenders.includes(sender)) {
        knownSenders.push(sender);
        userProperties.setProperty('knownSenders', JSON.stringify(knownSenders));
    }
}