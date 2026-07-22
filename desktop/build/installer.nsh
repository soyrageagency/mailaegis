; MailAegis — NSIS customisation.
;
; electron-builder generates a serviceable wizard, but a serviceable wizard for
; an unsigned security tool is exactly what people are taught to close. These
; two pages give the installer a voice: who wrote this, why it is free, and
; what would help.
;
; Crafted by SoyRage Agency — https://soyrage.es/

!macro customHeader
  ; A named installer reads better than "Setup" in the Windows task list.
  BrandingText "MailAegis — by SoyRage Agency · soyrage.es"
!macroend

; ---------------------------------------------------------------- welcome
!macro customWelcomePage
  !define MUI_WELCOMEPAGE_TITLE "MailAegis"
  !define MUI_WELCOMEPAGE_TEXT "Corporate Email Threat Analyzer.$\r$\n$\r$\nEvery message inspected — attachments, links, headers and intent. VirusTotal, ClamAV, SPF/DKIM/DMARC and an in-house phishing and BEC engine, in a mail client you can work in all day.$\r$\n$\r$\nFree and open source, built by SoyRage Agency. No account, no telemetry, no subscription.$\r$\n$\r$\nThis build is not code-signed, so Windows may warn you. The source is public if you would rather read it first: github.com/soyrageagency/mailaegis$\r$\n$\r$\nClick Next to continue."
  !insertmacro MUI_PAGE_WELCOME
!macroend

; ----------------------------------------------------------------- finish
; The thank-you page. Two ways to help, neither of them a nag: a star costs
; nothing, and a donation is entirely optional.
!macro customFinishPage
  !define MUI_FINISHPAGE_TITLE "Thank you for installing MailAegis"
  !define MUI_FINISHPAGE_TEXT "MailAegis is free and open source, and it stays that way.$\r$\n$\r$\nIf it saves your team from one wire-transfer fraud, a star on GitHub is all we ask — it is how other people find the project.$\r$\n$\r$\nIf it saved you more than that, the link below keeps the work going. Entirely optional, always."

  !define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXECUTABLE_FILENAME}"
  !define MUI_FINISHPAGE_RUN_TEXT "Open MailAegis now"

  !define MUI_FINISHPAGE_SHOWREADME ""
  !define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
  !define MUI_FINISHPAGE_SHOWREADME_TEXT "Star the project on GitHub (thank you!)"
  !define MUI_FINISHPAGE_SHOWREADME_FUNCTION openProjectPage

  !define MUI_FINISHPAGE_LINK "Support development — paypal.me/soyrageagency"
  !define MUI_FINISHPAGE_LINK_LOCATION "https://www.paypal.com/paypalme/soyrageagency"

  !insertmacro MUI_PAGE_FINISH
!macroend

Function openProjectPage
  ExecShell "open" "https://github.com/soyrageagency/mailaegis"
FunctionEnd

; ------------------------------------------------------------- uninstall
!macro customUnWelcomePage
  !define MUI_UNWELCOMEPAGE_TITLE "Removing MailAegis"
  !define MUI_UNWELCOMEPAGE_TEXT "Sorry to see it go.$\r$\n$\r$\nYour settings folder is left untouched, so reinstalling picks up where you left off. Nothing is sent anywhere when you uninstall.$\r$\n$\r$\nIf something did not work, we would genuinely like to know: github.com/soyrageagency/mailaegis/issues"
  !insertmacro MUI_UNPAGE_WELCOME
!macroend
