from django.core.mail import send_mail
from django.core.mail import EmailMessage
from django.conf import settings

import threading

class EmailThread(threading.Thread):
    '''For fast send email'''
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()
class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['email_subject'],body=data['email_body'],to=[data['to_email']])
        EmailThread(email).start()