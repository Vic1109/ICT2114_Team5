from google import genai

client = genai.Client(api_key="AIzaSyAwleKhZrh4lsOkaIV52Sav4Mn0nF5Q5bA")

response = client.models.generate_content(
    model="gemini-2.5-flash-preview-05-20", contents="you can test your prompts here"
)
print(response.text)