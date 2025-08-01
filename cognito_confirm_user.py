import boto3

client = boto3.client('cognito-idp', region_name='us-east-1')  # use your region

username = "rhpatel27@myseneca.ca"
temp_password = "Admin@123"          # temporary password you set in Cognito
new_password = "Admin@1234"      # new desired password
client_id = "10h15bak1b386c6euedevr0be0"  # your app client ID

# Step 1: Initiate auth with temp password
resp = client.initiate_auth(
    AuthFlow='USER_PASSWORD_AUTH',
    AuthParameters={
        'USERNAME': username,
        'PASSWORD': temp_password
    },
    ClientId=client_id
)

# Step 2: Respond to challenge to set new password
session = resp['Session']
challenge_resp = client.respond_to_auth_challenge(
    ClientId=client_id,
    ChallengeName='NEW_PASSWORD_REQUIRED',
    ChallengeResponses={
        'USERNAME': username,
        'NEW_PASSWORD': new_password
    },
    Session=session
)

print("✅ User password changed successfully. You can now log in via your Flask app.")
