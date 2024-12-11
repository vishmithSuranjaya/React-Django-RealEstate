from email.message import EmailMessage
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from log import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode 
from django.utils.encoding import force_bytes, force_str
from .tokens import generate_token  
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.core.mail import EmailMessage

# Create your views here.
def home(request):
    return render(request, "authentication/index.html")


def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        # Check if username is already taken
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists!")
            return redirect('signup')

        # Check if email is already registered
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered!")
            return redirect('signup')

        # Check username length
        if len(username) > 10:
            messages.error(request, "Username must be under 10 characters.")
            return redirect('signup')

        # Check if passwords match
        if pass1 != pass2:
            messages.error(request, "Passwords do not match!")
            return redirect('signup')

        # Check if username is alphanumeric
        if not username.isalnum():
            messages.error(request, "Username must be alphanumeric!")
            return redirect('signup')

        # Create the user
        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = firstname
        myuser.last_name = lastname
        myuser.is_active = False
        myuser.save()

        messages.success(request, "Your account has been created! We have sent an email confirmation.")

        # Email message
        subject = "Welcome to our website"
        message = (
            f"Hello {myuser.first_name}!\n\n"
            "Welcome to our website! Thank you for registering. "
            "Please verify your email address."
        )
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]

        # Send welcome email
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        # Confirmation link
        current_site = get_current_site(request)
        email_subject = "Confirm your email"
        message2 = render_to_string(
            'email_confirmation.html',
            {
                'name': myuser.first_name,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
                'token': generate_token.make_token(myuser),
            }
        )

        # Sending the confirmation email
        email = EmailMessage(
            subject=email_subject,
            body=message2,
            from_email=settings.EMAIL_HOST_USER,
            to=[myuser.email],
        )
        email.content_subtype = "html"  # Ensure the email is HTML
        email.fail_silently = False  # Raise error if email sending fails
        email.send()

        return redirect('signin')  # Redirect to signin page after successful signup

    return render(request, "authentication/signup.html")



def signin(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['pass1']

        # Authenticate the user
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            fname = user.first_name
            return render(request, "authentication/index.html", {'fname': fname})
        else:
            messages.error(request, "Bad credentials")
            return redirect('signin')

    return render(request, "authentication/signin.html")


from django.utils.encoding import force_str  # Ensure this import is present

def activate(request, uid64, token):
    try:
        # Decode the uid from base64
        uid = force_str(urlsafe_base64_decode(uid64))
        # Retrieve the user by the decoded uid
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    # The activation logic should be outside the exception handling block
    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        return redirect('home')
    else:
        return render(request, 'activation_failed.html')

         
    

def signout(request):
    logout(request)
    messages.success(request, "Successfully logged out!")
    return redirect('home')
