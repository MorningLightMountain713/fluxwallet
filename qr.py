import qrcode

# Data to be encoded
data = 'otpauth://totp/Flux%20Capacitor:Beavertown?secret=A7AIZT2BV5G7HDYX4R6TNL4GJO5MLTIB&issuer=Flux%20Capacitor&algorithm=SHA1&digits=6&period=30'
 
# Encoding data using make() function
img = qrcode.make(data)
 
# Saving as an image file
img.save('MyQRCode1.png')
