from mongoengine import Document, StringField

class User(Document):
    name = StringField(max_length=255,required=True)
    phoneNumber = StringField(max_length = 15,required = True, unique = True)
    pin = StringField(required=True)
    role = StringField(max_length=5,default = 'user')
    
    def __str__(self):
        return self.name