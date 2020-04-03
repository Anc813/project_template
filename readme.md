Start new project like this
`django-admin.py startproject --template=https://github.com/Anc813/project_template/zipball/master project`

Rename project to YOUR real projectname.
Create your local settings in settings directrory.
Provide readme for your project.
Your ready to go.
If you wish to make random string for your SECRET_KEY setting, you just need to type the following in interactive mode:

````
import string
from django.utils.crypto import get_random_string

print "SECRET_KEY = '%s'" % get_random_string(length=75, allowed_chars=string.digits + string.letters + string.punctuation)
Just copy/paste this in your settings file.
```
```
# Python3
import string
from django.utils.crypto import get_random_string

print ("SECRET_KEY = '%s'" % get_random_string(length=75, allowed_chars=''.join(set(string.digits + string.ascii_letters + string.punctuation) - set('\'"'))))
# Just copy/paste this in your settings file.
```


or just generate it online (if You are using python 3):

[django-secret-key-generator](http://www.miniwebtool.com/django-secret-key-generator/)


Replace
/path/to/project-root
/var/www/my-site

Then replace
/root/.virtualenvs/project_env
/home/.virtualenvs/site_env

Then replace
project
site
