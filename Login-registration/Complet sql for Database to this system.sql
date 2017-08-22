USE DB_A28195_ToDoWebServer
GO

CREATE TABLE Users (UserID INT NOT NULL PRIMARY KEY IDENTITY,
FirstName NVARCHAR(50) NOT NULL,
LastName NVARCHAR(50) NOT NULL,
EmailID NVARCHAR(254) NOT NULL,
DateOfBirth datetime,
Password NVARCHAR(MAX) NOT NULL,
IsEmailVerified BIT NOT NULL,
ActivationCode UNIQUEIDENTIFIER NOT NULL,
Failed_Logins INT NOT NULL,
Locked BIT NOT NULL,
TempPasswordSet BIT NOT NULL);


CREATE TABLE cryptokey (
id INT NOT NULL IDENTITY PRIMARY KEY,
UserID INT NOT NULL,
FOREIGN KEY (UserId) REFERENCES Users(UserID), 
cryptone NVARCHAR(250) NOT NULL, 
crypttwo NVARCHAR(250) NOT NULL, 
crypttree NVARCHAR(250) NOT NULL);


CREATE TABLE Email_Templates (ID INT NOT NULL PRIMARY KEY IDENTITY,
E_Subject NVARCHAR(150) NOT NULL,
E_Body NVARCHAR(MAX) NOT NULL);

INSERT INTO Email_Templates (E_Subject, E_Body) 
VALUES ('NO-REPLY Your account is successfully created!',
'<br/><br/>Your account for andersensoftwaredesign.com has been successfully created.
<br/> Please click on the below link to verify your account 
<br/><br/><a href=%>%"</a> ');

INSERT INTO Email_Templates (E_Subject, E_Body) 
VALUES ('NO-REPLY account re-activation',
'<br/><br/>User %user% would like their account for andersensoftwaredesign.com 
re-activated.
<br/> Please click on the below link to reactivate the account 
<br/><br/><a href=%>%"</a> ');

INSERT INTO Email_Templates (E_Subject, E_Body) 
VALUES ('NO-REPLY account re-activation',
'<br/><br/>Administartor for andersensoftwaredesign.com 
has been contacted for re-activation please avait reply mail can take up to 2 days.
<br/> ');

INSERT INTO Email_Templates (E_Subject, E_Body) 
VALUES ('NO-REPLY account re-activation',
'<br/><br/>The account %user% for andersensoftwaredesign.com 
has now been re-activated.<br/>if password has been forgotten please folow the guide
on andersensoftwaredesign.com
<br/>');

INSERT INTO Email_Templates (E_Subject, E_Body) 
VALUES ('NO-REPLY Temperary password',
'<br/><br/>This is a temporary password for andersensoftwaredesign.com 
and will only alow you to change your password.<br/> the password for %user% is %password%
<br/>');

