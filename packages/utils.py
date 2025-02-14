from django.conf import settings
import openai
from datetime import datetime, timedelta
from django.utils.timezone import now
import os
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from authentication.models import *
import json


openai.api_key = settings.OPENAI_API_KEY  #
def extract_actionable_steps(notes):
    """ Calls OpenAI API to extract actionable steps from doctor notes. """
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",  # Use gpt-4 or gpt-3.5-turbo
            messages=[
                {"role": "system", "content": "You are a medical assistant that extracts actionable steps from doctor notes."},
                {"role": "user", "content": f"Extract a checklist (immediate tasks) and a plan (scheduled actions) from these doctor notes: {notes}"}
            ],
            temperature=0.3
        )

        ai_response = response["choices"][0]["message"]["content"]

        # Expecting structured JSON-like response from the LLM
        return json.loads(ai_response)

    except Exception as e:
        return {"error": f"LLM processing failed: {str(e)}"}
