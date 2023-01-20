# import os
# from twilio.rest import Client


# # Find your Account SID and Auth Token at twilio.com/console
# # and set the environment variables. See http://twil.io/secure
# account_sid = "AC40d3bdecdedfe6fe5d97c506a9cc5279"  # os.environ["TWILIO_ACCOUNT_SID"]
# auth_token = "61b8ba5445f732f8c97ef4d6deb3acc0"  # os.environ["TWILIO_AUTH_TOKEN"]
# client = Client(account_sid, auth_token)

# new_factor = (
#     client.verify.v2.services("VA1c95a3bf279ec66467289fc8ee175d40")
#     .entities("big-chonk")
#     .new_factors.create(friendly_name="Beavertown", factor_type="totp")
# )

# print(new_factor.binding)


# Download the helper library from https://www.twilio.com/docs/python/install


# Download the helper library from https://www.twilio.com/docs/python/install
# Download the helper library from https://www.twilio.com/docs/python/install
import os

from twilio.rest import Client

# # Find your Account SID and Auth Token at twilio.com/console
# # and set the environment variables. See http://twil.io/secure
# account_sid = "AC40d3bdecdedfe6fe5d97c506a9cc5279"
# auth_token = "61b8ba5445f732f8c97ef4d6deb3acc0"
# client = Client(account_sid, auth_token)

# factors = (
#     client.verify.v2.services("VA1c95a3bf279ec66467289fc8ee175d40")
#     .entities("big-chonk")
#     .factors.list(limit=20)
# )

# for record in factors:
#     print(record.sid)




# # Find your Account SID and Auth Token at twilio.com/console
# # and set the environment variables. See http://twil.io/secure
# account_sid = "AC40d3bdecdedfe6fe5d97c506a9cc5279"
# auth_token = "61b8ba5445f732f8c97ef4d6deb3acc0"
# client = Client(account_sid, auth_token)

# factor = (
#     client.verify.v2.services("VA1c95a3bf279ec66467289fc8ee175d40")
#     .entities("big-chonk")
#     .factors("YF0263c653634ef6254c66bbe1b81b1ae8")
#     .update(auth_payload="249466")
# )

# print(factor.status)




# Find your Account SID and Auth Token at twilio.com/console
# and set the environment variables. See http://twil.io/secure
account_sid = "AC40d3bdecdedfe6fe5d97c506a9cc5279"
auth_token = "61b8ba5445f732f8c97ef4d6deb3acc0"
client = Client(account_sid, auth_token)

challenge = (
    client.verify.v2.services("VA1c95a3bf279ec66467289fc8ee175d40")
    .entities("big-chonk")
    .challenges.create(
        auth_payload="956156", factor_sid="YF0263c653634ef6254c66bbe1b81b1ae8"
    )
)

print(challenge.status)
