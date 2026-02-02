---
name: weather
description: Get current weather information for a location
---

When the user asks for weather information:

1. If they provide a location in $ARGUMENTS, use that location
2. If no location is provided, fetch weather for their current location (automatic)
3. Use the wttr.in service to get weather data
4. Display the weather information in a clean, readable format

To fetch weather:
- Use: curl "wttr.in/{location}?format=3" for a simple one-line format
- Or use: curl "wttr.in/{location}" for detailed weather with forecast
- For current location (no arguments): curl "wttr.in/?format=3"

Show:
- Current temperature and conditions
- Location name
- Brief description of what to expect today

Keep the response concise and helpful.
