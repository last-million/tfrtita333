export function buildSystemPrompt(config) {
  let prompt = config.systemPrompt || ''

  // Add tool-specific instructions
  if (config.tools) {
    if (config.tools.calendar?.enabled) {
      prompt += `\n\nCalendar Management:
- You can manage calendar events using the 'calendar' tool
- Use this to schedule meetings, check availability, and manage appointments
- Always confirm the time and date with the user before scheduling`
    }

    if (config.tools.gmail?.enabled) {
      prompt += `\n\nEmail Capabilities:
- You can send emails using the 'gmail' tool
- Use this for follow-ups, confirmations, and sending information
- Always confirm the email content with the user before sending`
    }

    if (config.tools.serp?.enabled) {
      prompt += `\n\nWeb Search:
- You can search the internet using the 'search' tool
- Use this to find current information and answer questions
- Always cite your sources when providing information from web searches`
    }
  }

  // Add knowledge base instructions
  if (config.knowledgeBase) {
    prompt += `\n\nKnowledge Base:
- You have access to the following knowledge sources:
${Object.entries(config.knowledgeBase)
  .filter(([_, source]) => source.enabled)
  .map(([name]) => `- ${name}`)
  .join('\n')}
- Use this information to provide accurate and contextual responses`
  }

  return prompt
}
