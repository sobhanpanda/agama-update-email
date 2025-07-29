[#ftl output_format="HTML"]
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>OTP Verification
	</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"></head>
<body><div class="otp-container"><div align="center" class="flex"><img src="https://gluu.org/wp-content/uploads/2020/12/logo.png" alt="Logo" id="inh1m"></div><div class="header"><i class="fas fa-key">
		</i>Email OTP Verification
	  </div><!-- ✅ Show Error Message -->
	  [#if errorMessage?? &amp;&amp; errorMessage?length gt 0]
	  <div role="alert" align="center" class="alert alert-danger mt-3 error"><p>${errorMessage}
		</p></div>
	  [/#if]
	  [#if matches?? &amp;&amp; !matches]
	  <div role="alert" align="center" class="alert alert-danger mt-3 error"><p>Invalid OTP. Please try again.
		</p></div>
	  [/#if]
	  <div class="content"><p class="text-center">A verification code has been sent to:
		</p><p class="text-center email-display">${email}
		</p><!-- OTP Submission Form --><form method="post" enctype="application/x-www-form-urlencoded"><div class="form-group"><label for="passcode" class="form-label">Enter OTP: <span class="required">*</span></label><input type="text" id="passcode" name="passcode" pattern="[0-9]+" required="" placeholder="000000" class="form-control"></div><div class="buttons"><button type="submit" class="btn btn-primary">Continue</button></div></form><!-- Resend Code --><form method="post" enctype="application/x-www-form-urlencoded" class="resend-form"><p class="text-sm text-center mt-4">Didn't receive the code?
		  </p><div align="center"><button type="submit" name="resend" value="yes" class="btn btn-secondary resend-btn">Resend Code</button></div></form></div></div></body>
<style>
	body {
	  font-family: Arial, sans-serif;
	  background-color: #f8f9fa;
	  display: flex;
	  justify-content: center;
	  align-items: center;
	  height: 100vh;
	  margin: 0;
	}
	.otp-container {
	  width: 100%;
	  max-width: 500px;
	  background: white;
	  border-radius: 5px;
	  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
	  overflow: hidden;
	}
	.header {
	  background: #28a745;
	  padding: 15px;
	  color: white;
	  font-size: 20px;
	  font-weight: bold;
	  display: flex;
	  align-items: center;
	}
	.header i {
	  margin-right: 10px;
	}
	.content {
	  padding: 20px;
	}
	.form-group {
	  margin-bottom: 15px;
	}
	.form-label {
	  font-weight: bold;
	  display: block;
	  margin-bottom: 5px;
	}
	.form-control {
	  width: 95%;
	  padding: 10px;
	  font-size: 14px;
	  border: 1px solid #ced4da;
	  border-radius: 5px;
	}
	.required {
	  color: red;
	}
	.error {
	  font-weight: bold;
	  color: red;
	}
	.email-display {
	  font-weight: bold;
	  color: #28a745;
	  font-size: 16px;
	  margin-bottom: 20px;
	}
	.buttons {
	  margin-top: 20px;
	  display: flex;
	  justify-content: center;
	}
	.btn {
	  padding: 10px 20px;
	  font-size: 15px;
	  border: none;
	  border-radius: 5px;
	  cursor: pointer;
	}
	.btn-primary {
	  background-color: #007bff;
	  color: white;
	}
	.btn-primary:hover {
	  background-color: #0056b3;
	}
	.btn-secondary {
	  background-color: #6c757d;
	  color: white;
	}
	.btn-secondary:hover {
	  background-color: #5a6268;
	}
	.resend-form {
	  margin-top: 15px;
	}
  </style>

</html>