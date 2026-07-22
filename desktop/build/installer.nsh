; MailAegis — NSIS customisation.
;
; electron-builder generates a serviceable wizard, but a serviceable wizard for
; an unsigned security tool is exactly what people are taught to close. The
; sidebar art carries most of that; this file adds the thank-you page.
;
; Deliberately small. electron-builder's own template defines many of these
; symbols before including this file, and makensis is invoked with warnings
; treated as errors — so every define is /redef, and nothing here declares a
; page or a function that the template might already own.
;
; Crafted by SoyRage Agency — https://soyrage.es/

!macro customHeader
  ; A named installer reads better than "Setup" in the Windows task list.
  BrandingText "MailAegis — by SoyRage Agency · soyrage.es"
!macroend

!macro customFinishPage
  !define /redef MUI_FINISHPAGE_TITLE "Thank you for installing MailAegis"
  !define /redef MUI_FINISHPAGE_TEXT "MailAegis is free and open source, and it stays that way.$\r$\n$\r$\nIf it saves your team from one wire-transfer fraud, a star on GitHub is all we ask — it is how other people find the project:$\r$\n     github.com/soyrageagency/mailaegis$\r$\n$\r$\nIf it saved you more than that, the link below keeps the work going. Entirely optional, always."

  !define /redef MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXECUTABLE_FILENAME}"
  !define /redef MUI_FINISHPAGE_RUN_TEXT "Open MailAegis now"

  !define /redef MUI_FINISHPAGE_LINK "Support development — paypal.me/soyrageagency"
  !define /redef MUI_FINISHPAGE_LINK_LOCATION "https://www.paypal.com/paypalme/soyrageagency"

  !insertmacro MUI_PAGE_FINISH
!macroend
