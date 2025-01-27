from django.core.mail import EmailMessage
import os
from twilio.rest import Client
from django.conf import settings

class Util:
  @staticmethod
  def send_email(data):
    email = EmailMessage(
      subject=data['subject'],
      body=data['body'],
      from_email=os.environ.get('EMAIL_FROM'),
      to=[data['to_email']]
    )
    email.send()






def send_sms(to_phone, otp):
    """
    Sends an SMS using Twilio.
    
    :param to_phone: Recipient's phone number (include country code, e.g., +1234567890)
    :param otp: OTP to include in the message
    :return: SID of the sent message
    """
    # Fetch Twilio credentials from settings
    twilio_env = settings.TWILIO_ENVIRONMENT
    credentials = settings.TWILIO_CREDENTIALS[twilio_env]

    # Initialize Twilio client
    client = Client(credentials["account_sid"], credentials["auth_token"])

    # Compose the SMS message
    message = f"{credentials['message_part1']}{otp}. {credentials['message_part2']}"

    # Send the message
    try:
        response = client.messages.create(
            body=message,
            from_=credentials["sms_from_number"],
            to=to_phone
        )
        return response.sid
    except Exception as e:
        raise RuntimeError(f"Failed to send SMS: {e}")
