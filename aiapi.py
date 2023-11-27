import openai 
import config 
import time



openai.api_key =config.DevelopmentConfig.OPENAI_KEY

def generateChatResponse(prompt):
    start_time = time.time()
    messages = []
    messages.append({"role": "system", "content": "You are a helpful assistant."})
    question = {}
    question['role'] = 'user'
    question['content'] = prompt
    messages.append(question)
    response = openai.ChatCompletion.create(model="gpt-3.5-turbo",messages=messages)
    try:
        answer = response['choices'][0]['message']['content'].replace('\n','<br>')
        end_time = time.time()
        response_time = end_time - start_time
    except:
        answer = 'Oops you beat the AI,try a different question , if the problem persists , come back later.'

    return answer + f" Response Time: {response_time}."


