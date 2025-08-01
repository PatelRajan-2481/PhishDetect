import boto3
from botocore.exceptions import ClientError

AWS_REGION = "us-east-1"  # ✅ your region
USER_POOL_ID = "us-east-1_p5iidf4Bn"  # 🔁 replace
CLIENT_ID = "10h15bak1b386c6euedevr0be0"  # ✅ from your app client

client = boto3.client("cognito-idp", region_name=AWS_REGION)

def login_user(email, password):
    try:
        resp = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password
            }
        )
        return resp['AuthenticationResult']['IdToken']
    except ClientError as e:
        print("Login error:", e.response['Error']['Message'])
        return None
