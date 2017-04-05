import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'fart'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
    def get(self):
        self.write('Welcome to Vladi\'s blog!')


##### USER stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h==make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


#### MODEL STUFF

class User(db.Model):
    name=db.StringProperty(required=True)
    pw_hash=db.StringProperty(required=True)
    email=db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u=User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u=cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    subject=db.StringProperty(required=True)
    content=db.TextProperty(required=True)
    created=db.DateTimeProperty(auto_now_add=True)
    like_count=db.IntegerProperty(default=0)
    author=db.ReferenceProperty(User)
    liked_by=db.ListProperty(int)
    last_modified=db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text=self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Comment(db.Model):
    post_id=db.ReferenceProperty(Post)
    comment_text=db.StringProperty(required=True)
    commented_by=db.ReferenceProperty(User)
    # [1,2,3,4,5] # [Key(),Key()]
    created = db.DateTimeProperty(auto_now_add=True)


##### BLOG STUFF

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class BlogFront(BlogHandler):
    def get(self):
        posts=Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect("/login")
            return
    
        key=db.Key.from_path('Post', int(post_id), parent=blog_key())
        post=db.get(key)

        if not post:
            return self.error(404)
        comments=db.Query(Comment).filter('post_id =',
                                          post.key()).order('-created')
        print "comments :", comments

        self.render("permalink.html", post=post,
                    user=self.user, comments=comments)

    def post(self, post_id):
        key=db.Key.from_path('Post', int(post_id), parent=blog_key())
        post=db.get(key)

        if not self.user:
            error="Only logged users can write comments"
            self.render("permalink.html", post=post, error=error)
            return

        post_key=post.key()
        comment_text=self.request.get('comment')
        commented_by=self.user.key()

        if comment_text=="":
            error="Please write a comment"
            self.render("permalink.html", post=post, error=error)
            return
        else:
            print post_id, comment_text, commented_by
            c=Comment(post_id=post_key, comment_text=comment_text,
                      commented_by=commented_by)
            c.put()
            time.sleep(0.1)
            self.redirect('/blog/%s' %str(post_id))


#Like the blog post
class LikeHandler(BlogHandler):
    def get(self, post_id):
        key=db.Key.from_path('Post', int(post_id), parent=blog_key())
        post=db.get(key)

        for l in post.liked_by:
            if l==self.user.key().id():
                error="You can like a post only once"
                self.render("permalink.html", post=post, error=error)
                return

        if not post:
            self.error(404)
            return
        elif post.author.key()==self.user.key():
            error="You can't like your posts, that is cheating"
            return self.render("permalink.html/", post=post, error=error)
        else:
            post.like_count=post.like_count+1
            post.liked_by.append(self.user.key().id())
            print "Liked by %d" %(self.user.key().id())
            post.put()
            time.sleep(0.1)
            self.render("permalink.html", post=post)


# Delete the blog post
class DeleteHandler(BlogHandler):
    def get(self, post_id):
        key=db.Key.from_path('Post', int(post_id), parent=blog_key())
        post=db.get(key)

        if not post:
            self.error(404)
            return
        elif post.author.key()!=self.user.key():
            error="Only the authors of the post can delete it"
            return self.render("permalink.html/", post=post, error=error)
        else:
            post.delete()
            time.sleep(0.1)
            self.redirect('/blog')


# Create a new blog post
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html", form_name="create a post")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        subject=self.request.get('subject')
        content=self.request.get('content')
        author=self.user.key()

        if subject and content:
            p=Post(parent=blog_key(), subject=subject,
                   content=content, author=author)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error="subject and content, please!"
            self.render("newpost.html", form_name="create a post",
                        subject=subject, content=content, error=error)


#Edit a blog post
class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post.author.key()!=self.user.key():
            error="Only the authors of the post can edit it"
            return self.render("permalink.html/", post=post, error=error)

        elif self.user:
            self.render("edit-post.html", form_name="edit a post", post=post,
                        subject=post.subject, content=post.content)
        else:
            self.redirect("/login")

    def post(self, post_id):
        key=db.Key.from_path('Post', int(post_id), parent=blog_key())
        post=db.get(key)

        if not post:
            return self.error(404)
    
        elif not self.user:
            return self.redirect('/blog')

        subject=self.request.get('subject')
        content=self.request.get('content')

        if post.author.key()!=self.user.key():
            error="Only the authors of the post can edit it"
            return self.render("permalink.html/", post=post, error=error)

        elif subject and content:
            post.subject=subject
            post.content=content
            post.put()
            time.sleep(0.1)
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error="subject and content, please!"
            self.render("edit-post.html", form_name="edit a post",
                        subject=subject, content=content,
                        error=error, post=post)


#### COMMENTS STUFF
#Edit a coment you made
class EditCommentHandler(BlogHandler):
    def get(self, comment_id):
        key=db.Key.from_path('Comment', int(comment_id))
        c=db.get(key)

        if not c:
            return self.error(404)
        key2=db.Key.from_path('Post', int(c.post_id.key().id()),
                              parent=blog_key())
        post=db.get(key2)

        if not post:
            return self.error(404)
        self.render("edit-comment.html",
                    form_name="Edit Comment", post=post, 
                    user=self.user, comment=c)

    def post(self, comment_id):
        key=db.Key.from_path('Comment', int(comment_id))
        c=db.get(key)
        if not c:
            return self.error(404)
        key2=db.Key.from_path('Post', int(c.post_id.key().id()),
                              parent=blog_key())
        post=db.get(key2)

        if not post:
            return self.error(404)

        if not self.user and c.commented_by == self.user.key():
            error = "You can only edit your comments"
            return self.render("edit-comment.html", post = post, 
                                user=self.user, comment=c, error=error)

        comment_text=" "
        comment_text = self.request.get('comment')

        if comment_text!="":
            c.comment_text = comment_text
            c.put()
            time.sleep(0.1)
        else:
            error="empty comments are not allowed"
            return self.render("edit-comment.html", post = post, 
                                user=self.user, comment=c, error=error)
        
        self.redirect('/blog/%s' % str(post.key().id()))    


#delete the comment, not the blog post

class DeleteCommentHandler(BlogHandler):
    def get(self, comment_id):
        key=db.Key.from_path('Comment', int(comment_id))
        c=db.get(key)
        key2=db.Key.from_path('Post', int(c.post_id.key().id()), parent=blog_key())
        post=db.get(key2)

        if not c:
            self.error(404)
            return
        elif c.commented_by==self.user.key():
            error="You can only delete the posts that you wrote"
            return self.render("permalink.html", post=post, error=error)
        else:
            c.delete()
            time.sleep(0.1)
        self.redirect('/blog/%s'%str(c.post_id.key().id()))


#USER MANAGEMENT

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error=False
        self.username=self.request.get('username')
        self.password=self.request.get('password')
        self.verify=self.request.get('verify')
        self.email=self.request.get('email')

        params=dict(username=self.username,
                    email=self.email)

        if not valid_username(self.username):
            params['error_username']="That's not a valid username."
            have_error=True

        if not valid_password(self.password):
            params['error_password']="That wasn't a valid password."
            have_error=True
        elif self.password!=self.verify:
            params['error_verify']="Your passwords didn't match."
            have_error=True

        if not valid_email(self.email):
            params['error_email']="That's not a valid email."
            have_error=True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg='That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u=User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.render('welcome.html', username=self.username)


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username=self.request.get('username')
        password=self.request.get('password')

        u=User.login(username, password)
        if u:
            self.login(u)
            self.render('welcome.html', username=username)
        else:
            msg='Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/register')

# HANDLERS

app = webapp2.WSGIApplication([('/', Login),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/like/([0-9]+)', LikeHandler),
                               ('/blog/delete/([0-9]+)', DeleteHandler),
                               ('/blog/edit/([0-9]+)', EditPost),
                               ('/blog/deleteComment/([0-9]+)', DeleteCommentHandler),
                               ('/blog/editComment/([0-9]+)', EditCommentHandler),                              
                               ('/blog/newpost', NewPost),
                               ('/register', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ],
                              debug=True)
