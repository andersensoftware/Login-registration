using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using RegistrationAndLogin.Models;
using System.Net.Mail;
using System.Net;
using System.Web.Security;
using Encryption;
using System.Data.Entity.Validation;


namespace RegistrationAndLogin.Controllers
{
    public class UserSettingsController : Controller
    {
        // GET: UserSettings
        [HttpGet]
        public ActionResult ResetPassword()
        {
            return View();
        }
        [HttpPost]
        public ActionResult ResetPassword(ResetPassword model, string ReturnUrl = "")
        {
            string message = "";
            bool Status = false;
            string type = "Success";
            using(MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var user = dc.Users.Where(x => x.EmailID == model.EmailID).FirstOrDefault();
                if (!user.Locked)
                {
                    message = "your account has not been locked please try forgotten password.";
                    type = "Error";
                    Status = true;
                }
                else
                {
                    if (user != null)
                    {
                       
                            if (SendReActiveMail(user))
                            {
                                message = "Request has been sent to admin.";
                                type = "Success";
                                Status = true;
                            }
                            else
                            {
                                message = "Request has not been sent to admin. try writing a mail directly to admin if the error continues Admin-Mail: admin@andersensoftwaredesign.com";
                                type = "Error";
                                Status = true;
                            }
                        
                    }
                }
            }

            ViewBag.Message = message;
            ViewBag.Status = Status;
            ViewBag.Type = type;
            return View();
        }

        [HttpGet]
        public ActionResult AdminResetAccount(string id)
        {
            bool Status = false;
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                dc.Configuration.ValidateOnSaveEnabled = false; // This line I have added here to avoid 
                                                                // Confirm password does not match issue on save changes
                var v = dc.Users.Where(a => a.ActivationCode == new Guid(id)).FirstOrDefault();
                if (v != null)
                {
                    v.Locked = false;
                    v.Failed_Logins = 0;
                    dc.SaveChanges();
                    Status = true;
                    
                        SendReActiveMailResponse(v);
                    
                }
                else
                {
                    ViewBag.Message = "Invalid Request";
                }
            }
            ViewBag.Status = Status;
            return View();
        }

        [Authorize]
        public ActionResult ChangePassword()
        {
            return View();
        }
        //Login POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ChangePassword(ChangePassword model, string ReturnUrl = "")
        {
            string message = "";
            bool Status = false;
            string type = "Success";
            var userControl = new UserController();
            if (!userControl.checkPasswordStrengt(model.NewPassword))
            {
                message = "password does not match rules please include one uppercase letter, one number and one of these symbols !,@,#,$,%,^,&,*,?,_,~,-,£,(,)";
                Status = true;
                type = "Error";
            }
            else
            {
                var CurrentUserEmail = HttpContext.User.Identity.Name;
                using (MyDatabaseEntities dc = new MyDatabaseEntities())
                {
                    var user = dc.Users.Where(x => x.EmailID == CurrentUserEmail).FirstOrDefault();
                    var getPassword = dc.Users.Where(u => u.EmailID == user.EmailID).Select(u => u.Password);
                    var materializePassword = getPassword.ToList();
                    var password = materializePassword[0];
                    var getCryptoOne = dc.cryptokeys.Where(u => u.UserID == user.UserID).Select(u => u.cryptone);
                    var materializeCryptoOne = getCryptoOne.ToList();
                    var CryptoOne = materializeCryptoOne[0];
                    var getCryptoTwo = dc.cryptokeys.Where(u => u.UserID == user.UserID).Select(u => u.crypttwo);
                    var materializeCryptoTwo = getCryptoTwo.ToList();
                    var CryptoTwo = materializeCryptoTwo[0];
                    var getCryptoTree = dc.cryptokeys.Where(u => u.UserID == user.UserID).Select(u => u.crypttree);
                    var materializeCryptoTree = getCryptoTree.ToList();
                    var keyTree = materializeCryptoTree[0];
                    var keyTwo = CustomDecrypt.Decrypt(CryptoTwo, keyTree);
                    var keyOne = CustomDecrypt.Decrypt(CryptoOne, keyTwo);
                    var decryptPassword = CustomDecrypt.Decrypt(password, keyOne);

                    if ((string.Compare(model.Password, decryptPassword) == 0))
                    {
                        string NewkeyOne = CustomEnrypt.RandomString(15);
                        string NewkeyTwo = CustomEnrypt.RandomString(15);
                        string NewkeyTree = CustomEnrypt.RandomString(15);
                        user.Password = CustomEnrypt.Encrypt(model.NewPassword, NewkeyOne);
                        //user.Password = Crypto.Hash(user.Password);
                        user.ConfirmPassword = CustomEnrypt.Encrypt(model.ConfirmPassword, NewkeyOne);
                        var crypto = dc.cryptokeys.Where(x => x.UserID == user.UserID).FirstOrDefault();
                        crypto.cryptone = CustomEnrypt.Encrypt(NewkeyOne, NewkeyTwo);
                        crypto.crypttwo = CustomEnrypt.Encrypt(NewkeyTwo, NewkeyTree);
                        crypto.crypttree = NewkeyTree;
                        try
                        {
                            if(user.TempPasswordSet)
                            {
                                user.TempPasswordSet = false;
                                user.Failed_Logins = 0;
                            }
                            dc.SaveChanges();
                            message = "Your password have been successfuly changed.";
                            Status = true;
                        }
                        catch (DbEntityValidationException ex)
                        {
                            foreach (var entityValidationErrors in ex.EntityValidationErrors)
                            {
                                foreach (var validationError in entityValidationErrors.ValidationErrors)
                                {
                                    Response.Write("Property: " + validationError.PropertyName + " Error: " + validationError.ErrorMessage);
                                }
                            }
                        }
                    }
                    else
                    {
                        message = "Password does not match if Error continues contact administrator.";
                        Status = true;
                        type = "Error";
                    }
                }
            }
            
            ViewBag.Message = message;
            ViewBag.Status = Status;
            ViewBag.Type = type;
            return View();
        }
        [HttpGet]
            public ActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]      
        public ActionResult ForgotPassword(ForgotPassword model, string ReturnUrl = "")
        {
            string message = "";
            bool Status = false;
            string type = "Success";
            using(MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var user = dc.Users.Where(x => x.EmailID == model.EmailID).FirstOrDefault();
                if(user != null)
                {
                    string psw = Encryption.CustomEnrypt.GeneratePassword(10);
                    var usr = new UserController();
                    while (!usr.checkPasswordStrengt(psw))
                    {
                        psw = Encryption.CustomEnrypt.GeneratePassword(10);
                    }
                    string NewkeyOne = CustomEnrypt.RandomString(15);
                    string NewkeyTwo = CustomEnrypt.RandomString(15);
                    string NewkeyTree = CustomEnrypt.RandomString(15);
                    user.Password = CustomEnrypt.Encrypt(psw, NewkeyOne);
                    //user.Password = Crypto.Hash(user.Password);
                    user.ConfirmPassword = CustomEnrypt.Encrypt(psw, NewkeyOne);
                    user.TempPasswordSet = true;
                    var crypto = dc.cryptokeys.Where(x => x.UserID == user.UserID).FirstOrDefault();
                    crypto.cryptone = CustomEnrypt.Encrypt(NewkeyOne, NewkeyTwo);
                    crypto.crypttwo = CustomEnrypt.Encrypt(NewkeyTwo, NewkeyTree);
                    crypto.crypttree = NewkeyTree;
                    try
                    {
                        dc.SaveChanges();
                        SendTempPassword(user, psw);
                        message = "temperary password send to given mail";
                        type = "Success";
                        Status = true;
                    }
                    catch (DbEntityValidationException ex)
                    {
                        foreach (var entityValidationErrors in ex.EntityValidationErrors)
                        {
                            foreach (var validationError in entityValidationErrors.ValidationErrors)
                            {
                                Response.Write("Property: " + validationError.PropertyName + " Error: " + validationError.ErrorMessage);
                            }
                        }
                    }
                   
                }
                else
                {
                    message = "there are no user matching the given email address please contact administartor if error continues";
                    type = "Error";
                    Status = true;
                }
            }

            ViewBag.Message = message;
            ViewBag.Status = Status;
            ViewBag.Type = type;
            return View();
        }

        [NonAction]
        public bool SendReActiveMail(User user)
        {
            var verifyUrl = "/UserSettings/AdminResetAccount/" + user.ActivationCode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl);
            var DB = new MyDatabaseEntities();
            var fromEmail = new MailAddress("from mail");
            var toEmail = new MailAddress("to mail");
            //string subject = DB.Email_Templates.Where(u => u.ID == 2).Select(u => u.E_Subject).FirstOrDefault();
            //string body = DB.Email_Templates.Where(u => u.ID == 2).Select(u => u.E_Body).FirstOrDefault();
            var smtp = new SmtpClient("smtp client");
            NetworkCredential Credentials = new NetworkCredential("site credentials", "********");
            smtp.Credentials = Credentials;
            var messageAdmin = new MailMessage();
            messageAdmin.Subject = DB.Email_Templates.Where(u => u.ID == 2).Select(u => u.E_Subject).FirstOrDefault();
            var body = DB.Email_Templates.Where(u => u.ID == 2).Select(u => u.E_Body).FirstOrDefault().Replace("%user%", user.EmailID);
            messageAdmin.Body = body.Replace("%", link);
            messageAdmin.IsBodyHtml = true;
            messageAdmin.From = fromEmail;
            messageAdmin.To.Add(toEmail);

            var messageUser = new MailMessage();
            messageUser.Subject = DB.Email_Templates.Where(u => u.ID == 3).Select(u => u.E_Subject).FirstOrDefault();
            messageUser.Body = DB.Email_Templates.Where(u => u.ID == 3).Select(u => u.E_Body).FirstOrDefault();
            messageUser.IsBodyHtml = true;
            messageUser.From = fromEmail;
            messageUser.To.Add(user.EmailID);

            try
            {
                smtp.Send(messageUser);
                smtp.Send(messageAdmin);
                return true;
            }
            catch
            {
                return false;
            }

        }
        public void SendReActiveMailResponse(User user)
        {
            var DB = new MyDatabaseEntities();
            var fromEmail = new MailAddress("*");
            var smtp = new SmtpClient("*");
            NetworkCredential Credentials = new NetworkCredential("*", "*");
            smtp.Credentials = Credentials;
            var message = new MailMessage();
            message.Subject = DB.Email_Templates.Where(u => u.ID == 4).Select(u => u.E_Subject).FirstOrDefault();
            message.Body = DB.Email_Templates.Where(u => u.ID == 4).Select(u => u.E_Body).FirstOrDefault().Replace("%user%", user.EmailID);
            message.IsBodyHtml = true;
            message.From = fromEmail;
            message.To.Add(user.EmailID);


            smtp.Send(message);


        }

        public void SendTempPassword(User user, string psw)
        {
            var DB = new MyDatabaseEntities();
            var fromEmail = new MailAddress("*");
            var smtp = new SmtpClient("*");
            var password = "<strong>" + psw + "</strong>";
            NetworkCredential Credentials = new NetworkCredential("*", "*");
            smtp.Credentials = Credentials;
            var message = new MailMessage();
            message.Subject = DB.Email_Templates.Where(u => u.ID == 5).Select(u => u.E_Subject).FirstOrDefault();
            var body = DB.Email_Templates.Where(u => u.ID == 5).Select(u => u.E_Body).FirstOrDefault().Replace("%user%", user.EmailID);
            message.Body = body.Replace("%password%", password);
            message.IsBodyHtml = true;
            message.From = fromEmail;
            message.To.Add(user.EmailID);


            smtp.Send(message);


        }
    }
}