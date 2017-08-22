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
using System.Text;
using System.Text.RegularExpressions;

namespace RegistrationAndLogin.Controllers
{
    public class UserController : Controller
    {
       //Registration Action
        [HttpGet]
        public ActionResult Registration()
        {
            return View();
        }
        //Registration POST action 
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Registration([Bind(Exclude = "IsEmailVerified,ActivationCode")] User user)
        {
            bool Status = false;
            string message = "";
            //
            // Model Validation 
            if (ModelState.IsValid)
            {

                #region //Email is already Exist 
                var isExist = IsEmailExist(user.EmailID);
                if (isExist)
                {
                    ModelState.AddModelError("EmailExist", "Email already exist");
                    return View(user);
                }
                if (!checkPasswordStrengt(user.Password))
                {
                    message = "password does not match rules please include one uppercase letter, one number and one of these symbols !,@,#,$,%,^,&,*,?,_,~,-,£,(,)";
                    Status = true;                    
                }
                else
                {
                    #endregion

                    #region Generate Activation Code 
                    user.ActivationCode = Guid.NewGuid();
                    #endregion

                    #region  Password Hashing 
                    string keyOne = CustomEnrypt.RandomString(15);
                    string keyTwo = CustomEnrypt.RandomString(15);
                    string keyTree = CustomEnrypt.RandomString(15);
                    user.Password = CustomEnrypt.Encrypt(user.Password, keyOne);
                    //user.Password = Crypto.Hash(user.Password);
                    user.ConfirmPassword = CustomEnrypt.Encrypt(user.ConfirmPassword, keyOne);
                    #endregion
                    user.IsEmailVerified = false;

                    #region Save to Database
                    using (MyDatabaseEntities dc = new MyDatabaseEntities())
                    {
                        User new_user = dc.Users.Create();
                        new_user = user;
                        cryptokey crypto = dc.cryptokeys.Create();
                        crypto.cryptone = CustomEnrypt.Encrypt(keyOne, keyTwo);
                        crypto.crypttwo = CustomEnrypt.Encrypt(keyTwo, keyTree);
                        crypto.crypttree = keyTree;
                        dc.Users.Add(new_user);
                        dc.cryptokeys.Add(crypto);
                        try
                        {
                            dc.SaveChanges();
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

                        //Send Email to User
                        SendVerificationLinkEmail(user.EmailID, user.ActivationCode.ToString());
                        message = "Registration successfully done. Account activation link " +
                            " has been sent to your email id:" + user.EmailID;
                        Status = true;
                    }
                    #endregion
                }
            }
            else
            {
                message = "Invalid Request";
            }

            ViewBag.Message = message;
            ViewBag.Status = Status;
            return View(user);
        }

        public bool checkPasswordStrengt(string password)
        {
            int score = 1;

            if (password.Length >= 8 )
                score++;
            if (Regex.IsMatch(password, @"[0-9]+(\.[0-9][0-9]?)?", RegexOptions.ECMAScript))   //number only //"^\d+$" if you need to match more than one digit.
                score++;
            if (Regex.IsMatch(password, @"^(?=.*[a-z])(?=.*[A-Z]).+$", RegexOptions.ECMAScript)) //both, lower and upper case
                score++;
            if (Regex.IsMatch(password, @"[!,@,#,$,%,^,&,*,?,_,~,-,£,(,)]", RegexOptions.ECMAScript)) //^[A-Z]+$
                score++;
            if (score != 5)
            {
                return false;
            }
            else
            {
                return true;
            }
           
        }
        //Verify Account    

        [HttpGet]
        public ActionResult VerifyAccount(string id)
        {
            bool Status = false;
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                dc.Configuration.ValidateOnSaveEnabled = false; // This line I have added here to avoid 
                                                                // Confirm password does not match issue on save changes
                var v = dc.Users.Where(a => a.ActivationCode == new Guid(id)).FirstOrDefault();
                if (v != null)
                {
                    v.IsEmailVerified = true;
                    dc.SaveChanges();
                    Status = true;
                }
                else
                {
                    ViewBag.Message = "Invalid Request";
                }
            }
            ViewBag.Status = Status;
            return View();
        }

        //Login 
        [HttpGet]
        public ActionResult Login()
        {
            return View();
        }

        //Login POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(UserLogin login, string ReturnUrl="")
        {
            bool Status = false;
            string message = "";
            string type = "Success";
            using (MyDatabaseEntities db = new MyDatabaseEntities())
            {
                //var v = dc.Users.Where(a => a.EmailID == login.EmailID).FirstOrDefault();

                var emailCheck = db.Users.FirstOrDefault(u => u.EmailID == login.EmailID);
                var usr_id = db.Users.Where(u => u.EmailID == login.EmailID).Select(u => u.UserID).FirstOrDefault();
                var getPassword = db.Users.Where(u => u.EmailID == login.EmailID).Select(u => u.Password);
                var materializePassword = getPassword.ToList();
                var password = materializePassword[0];
                var getCryptoOne = db.cryptokeys.Where(u => u.UserID == usr_id).Select(u => u.cryptone);
                var materializeCryptoOne = getCryptoOne.ToList();
                var CryptoOne = materializeCryptoOne[0];
                var getCryptoTwo = db.cryptokeys.Where(u => u.UserID == usr_id).Select(u => u.crypttwo);
                var materializeCryptoTwo = getCryptoTwo.ToList();
                var CryptoTwo = materializeCryptoTwo[0];
                var getCryptoTree = db.cryptokeys.Where(u => u.UserID == usr_id).Select(u => u.crypttree);
                var materializeCryptoTree = getCryptoTree.ToList();
                var keyTree = materializeCryptoTree[0];
                var keyTwo = CustomDecrypt.Decrypt(CryptoTwo, keyTree);
                var keyOne = CustomDecrypt.Decrypt(CryptoOne, keyTwo);
                var decryptPassword = CustomDecrypt.Decrypt(password, keyOne);
                //TODO: add decrypt af decryptkey using master decryptkey
                var user = db.Users.Where(u => u.EmailID == login.EmailID).FirstOrDefault();
                if (user != null && user.IsEmailVerified)
                {
                    if ((string.Compare(login.Password,decryptPassword) == 0) && !(user.Locked))
                    {
                        int timeout = login.RememberMe ? 525600 : 20; // 525600 min = 1 year
                        var ticket = new FormsAuthenticationTicket(login.EmailID, login.RememberMe, timeout);
                        string encrypted = FormsAuthentication.Encrypt(ticket);
                        var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encrypted);
                        cookie.Expires = DateTime.Now.AddMinutes(timeout);
                        cookie.HttpOnly = true;
                        Response.Cookies.Add(cookie);

                        if (user.TempPasswordSet)
                        {
                            return RedirectToAction("ChangePassword", "UserSettings");
                        }

                        if (Url.IsLocalUrl(ReturnUrl))
                        {
                            return Redirect(ReturnUrl);
                        }
                        else
                        {
                            return RedirectToAction("Index", "Home");
                        }
                    }
                    else
                    {
                        if (user.Failed_Logins < 3)
                        {
                            user.Failed_Logins++;
                            message = "Invalid email or password";
                            type = "Error";
                            Status = true;
                        }
                        else if (user.Failed_Logins == 3 || user.Locked)
                        {
                            user.Locked = true;
                            Status = true;
                            type = "Error";
                            message = "To many log in attemtes you have been locked out please contact system admin to be unlocked.";
                        }
                        try
                        {
                            user.ConfirmPassword = user.Password;
                            db.SaveChanges();
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
                }
                else
                {
                    if(user == null)
                    {
                        message = "User does not exist ";
                        Status = true;
                        type = "Error";
                    }
                    if (!user.IsEmailVerified)
                    {
                        message = "Please verify your account";
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

        //Logout
        //[Authorize]
        //[HttpPost]
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("FrontPage", "Home");
        }


        [NonAction]
        public bool IsEmailExist(string emailID)
        {
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var v = dc.Users.Where(a => a.EmailID == emailID).FirstOrDefault();
                return v != null;
            }
        }

        //ToDo change email password to come from encrypted database table
        //mail function to send account varification mail using smarterasp.net mail
        [NonAction]
        public void SendVerificationLinkEmail(string emailID, string activationCode)
        {
            var verifyUrl = "/User/VerifyAccount/" + activationCode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl);
            var DB = new MyDatabaseEntities();
            var fromEmail = new MailAddress("Your mail from here");
            var toEmail = new MailAddress(emailID);
            string subject = DB.Email_Templates.Where(u => u.ID == 1).Select(u => u.E_Subject).FirstOrDefault();
            string body = DB.Email_Templates.Where(u => u.ID == 1).Select(u => u.E_Body).FirstOrDefault();            
            var smtp = new SmtpClient("your smtp client here");            
            NetworkCredential Credentials = new NetworkCredential("YourWebsitehere", "*********");
            smtp.Credentials = Credentials;
            using (var message = new MailMessage(fromEmail, toEmail)
            {
                Subject = subject,
                Body = body.Replace("%", link),
                IsBodyHtml = true
            })
                smtp.Send(message);
        }
        
    }

   
}