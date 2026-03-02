#!/usr/bin/env python3
"""
Smart Romanian translation tool for Django .po files.

Modes:
  stats     - Show per-app translation coverage statistics
  generate  - Generate review YAML from untranslated entries (dictionary + AI)
  apply     - Apply approved translations from review YAML back to .po

Usage:
  translate_po.py stats <po-file>
  translate_po.py generate <po-file> [-o review.yaml] [--claude] [--model haiku] [--batch-size 30]
  translate_po.py apply <review.yaml> [--compile] [--dry-run] [--backup]

Flags: --dry-run, --backup, --include-fuzzy
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import polib
import yaml

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dictionary engine — exact matches (~300+ entries)
# ---------------------------------------------------------------------------

EXACT_TRANSLATIONS: dict[str, str] = {
    # Django built-in field errors
    "This field is required.": "Acest câmp este obligatoriu.",
    "Enter a valid email address.": "Introduceți o adresă de email validă.",
    "Enter a valid URL.": "Introduceți un URL valid.",
    "Enter a valid date.": "Introduceți o dată validă.",
    "Enter a valid time.": "Introduceți o oră validă.",
    "Enter a valid date/time.": "Introduceți o dată și oră validă.",
    "Enter a valid integer.": "Introduceți un număr întreg valid.",
    "Enter a valid decimal number.": "Introduceți un număr zecimal valid.",
    "Enter a valid IPv4 address.": "Introduceți o adresă IPv4 validă.",
    "Enter a valid IPv6 address.": "Introduceți o adresă IPv6 validă.",
    "Enter a whole number.": "Introduceți un număr întreg.",
    "Ensure this value is less than or equal to %(limit_value)s.": "Asigurați-vă că această valoare este mai mică sau egală cu %(limit_value)s.",
    "Ensure this value is greater than or equal to %(limit_value)s.": "Asigurați-vă că această valoare este mai mare sau egală cu %(limit_value)s.",
    "Ensure this value has at most %(limit_value)d character (truncated).": "Asigurați-vă că această valoare are cel mult %(limit_value)d caracter.",
    "Ensure this value has at most %(limit_value)d characters (truncated).": "Asigurați-vă că această valoare are cel mult %(limit_value)d caractere.",
    "Ensure this value has at least %(limit_value)d character (truncated).": "Asigurați-vă că această valoare are cel puțin %(limit_value)d caracter.",
    "Ensure this value has at least %(limit_value)d characters (truncated).": "Asigurați-vă că această valoare are cel puțin %(limit_value)d caractere.",
    "This value may not be null.": "Această valoare nu poate fi nulă.",
    "This field may not be null.": "Acest câmp nu poate fi nul.",
    "This field may not be blank.": "Acest câmp nu poate fi gol.",
    "A valid integer is required.": "Este necesar un număr întreg valid.",
    "A valid number is required.": "Este necesar un număr valid.",
    "Ensure that there are no more than %(max_digits)s digits in total.": "Asigurați-vă că nu există mai mult de %(max_digits)s cifre în total.",
    "Ensure that there are no more than %(max_decimal_places)s decimal places.": "Asigurați-vă că nu există mai mult de %(max_decimal_places)s zecimale.",
    "Ensure that there are no more than %(max_whole_digits)s digits before the decimal point.": "Asigurați-vă că nu există mai mult de %(max_whole_digits)s cifre înainte de virgulă.",
    "Select a valid choice. %(value)s is not one of the available choices.": "Selectați o opțiune validă. %(value)s nu este una dintre opțiunile disponibile.",
    "Select a valid choice. That choice is not one of the available choices.": "Selectați o opțiune validă. Opțiunea aleasă nu este disponibilă.",
    '"%(pk_value)s" is not a valid value.': '"%(pk_value)s" nu este o valoare validă.',
    "Please enter a correct %(field_labels)s and password. Note that both fields may be case-sensitive.": "Introduceți %(field_labels)s și parola corectă. Ambele câmpuri sunt sensibile la majuscule.",
    "Your old password was entered incorrectly. Please enter it again.": "Parola veche a fost introdusă incorect. Introduceți-o din nou.",
    "The two password fields didn't match.": "Cele două câmpuri de parolă nu se potrivesc.",
    "This account is inactive.": "Acest cont este inactiv.",
    "Please correct the error below.": "Vă rugăm să corectați eroarea de mai jos.",
    "Please correct the errors below.": "Vă rugăm să corectați erorile de mai jos.",
    "No %(verbose_name)s found matching the query": "Nu s-a găsit niciun %(verbose_name)s care să corespundă căutării",
    "%(model_name)s with this %(field_labels)s already exists.": "%(model_name)s cu acest %(field_labels)s există deja.",
    # Auth / Users
    "Log in": "Autentificare",
    "Log out": "Deconectare",
    "Login": "Autentificare",
    "Logout": "Deconectare",
    "Sign in": "Conectare",
    "Sign up": "Înregistrare",
    "Sign out": "Deconectare",
    "Register": "Înregistrare",
    "Username": "Nume utilizator",
    "Email": "Email",
    "Email address": "Adresă de email",
    "Password": "Parolă",
    "Confirm password": "Confirmați parola",
    "Old password": "Parolă veche",
    "New password": "Parolă nouă",
    "Change password": "Schimbați parola",
    "Reset password": "Resetați parola",
    "Forgot password?": "Ați uitat parola?",
    "Remember me": "Ține-mă minte",
    "Profile": "Profil",
    "Account": "Cont",
    "Settings": "Setări",
    "Two-factor authentication": "Autentificare în doi pași",
    "Enable two-factor authentication": "Activați autentificarea în doi pași",
    "Disable two-factor authentication": "Dezactivați autentificarea în doi pași",
    "Verification code": "Cod de verificare",
    "Backup codes": "Coduri de rezervă",
    "Two-factor authentication is enabled.": "Autentificarea în doi pași este activată.",
    "Two-factor authentication is disabled.": "Autentificarea în doi pași este dezactivată.",
    "Invalid verification code.": "Cod de verificare invalid.",
    "Verification code expired.": "Codul de verificare a expirat.",
    # Common UI
    "Save": "Salvați",
    "Save changes": "Salvați modificările",
    "Cancel": "Anulați",
    "Delete": "Ștergeți",
    "Edit": "Editați",
    "Update": "Actualizați",
    "Submit": "Trimiteți",
    "Confirm": "Confirmați",
    "Back": "Înapoi",
    "Next": "Următor",
    "Previous": "Anterior",
    "Continue": "Continuați",
    "Close": "Închideți",
    "Search": "Căutați",
    "Filter": "Filtrați",
    "Reset": "Resetați",
    "Clear": "Ștergeți",
    "Export": "Exportați",
    "Import": "Importați",
    "Download": "Descărcați",
    "Upload": "Încărcați",
    "Add": "Adăugați",
    "Remove": "Eliminați",
    "View": "Vizualizați",
    "Details": "Detalii",
    "Actions": "Acțiuni",
    "Status": "Stare",
    "Date": "Dată",
    "Created": "Creat",
    "Updated": "Actualizat",
    "Deleted": "Șters",
    "Active": "Activ",
    "Inactive": "Inactiv",
    "Enabled": "Activat",
    "Disabled": "Dezactivat",
    "Yes": "Da",
    "No": "Nu",
    "None": "Niciunul",
    "All": "Toate",
    "Loading...": "Se încarcă...",
    "Please wait...": "Vă rugăm să așteptați...",
    "Error": "Eroare",
    "Success": "Succes",
    "Warning": "Avertisment",
    "Info": "Informație",
    "Name": "Nume",
    "Description": "Descriere",
    "Notes": "Note",
    "Total": "Total",
    "Subtotal": "Subtotal",
    "Amount": "Sumă",
    "Select": "Selectați",
    "Choose": "Alegeți",
    "Optional": "Opțional",
    "Required": "Obligatoriu",
    "Pending": "În așteptare",
    "Approved": "Aprobat",
    "Rejected": "Respins",
    "Completed": "Finalizat",
    "Processing": "În procesare",
    "Cancelled": "Anulat",
    "Refunded": "Rambursat",
    "Draft": "Schiță",
    "Published": "Publicat",
    "Archived": "Arhivat",
    "Expired": "Expirat",
    # PRAHO / Hosting domain
    "Customer": "Client",
    "Customers": "Clienți",
    "Invoice": "Factură",
    "Invoices": "Facturi",
    "Proforma invoice": "Proformă",
    "Proforma invoices": "Proformate",
    "Proforma": "Proformă",
    "Order": "Comandă",
    "Orders": "Comenzi",
    "Product": "Produs",
    "Products": "Produse",
    "Subscription": "Abonament",
    "Subscriptions": "Abonamente",
    "Domain": "Domeniu",
    "Domains": "Domenii",
    "Hosting": "Găzduire",
    "Provider": "Furnizor",
    "Providers": "Furnizori",
    "Support ticket": "Bilet de suport",
    "Support tickets": "Bilete de suport",
    "Ticket": "Bilet",
    "Tickets": "Bilete",
    "CUI": "CUI",
    "VAT": "TVA",
    "VAT number": "Număr TVA",
    "Tax ID": "CUI",
    "Company name": "Denumire firmă",
    "Company": "Companie",
    "Address": "Adresă",
    "City": "Oraș",
    "County": "Județ",
    "Country": "Țară",
    "Postal code": "Cod poștal",
    "Phone": "Telefon",
    "Phone number": "Număr de telefon",
    "Bank account": "Cont bancar",
    "IBAN": "IBAN",
    "Payment": "Plată",
    "Payments": "Plăți",
    "Price": "Preț",
    "Prices": "Prețuri",
    "Currency": "Monedă",
    "Due date": "Dată scadentă",
    "Issue date": "Dată emitere",
    "Invoice number": "Număr factură",
    "Serial number": "Număr serial",
    "Quantity": "Cantitate",
    "Unit price": "Preț unitar",
    "Tax": "Impozit",
    "Discount": "Reducere",
    "Billing": "Facturare",
    "Billing address": "Adresă de facturare",
    "Renewal": "Reînnoire",
    "Renew": "Reînnoiți",
    "Expire": "Expirare",
    "Expiration date": "Dată expirare",
    "Registration": "Înregistrare",
    "Transfer": "Transfer",
    "Nameserver": "Server de nume",
    "Nameservers": "Servere de nume",
    "DNS": "DNS",
    "SSL certificate": "Certificat SSL",
    "Bandwidth": "Lățime de bandă",
    "Storage": "Spațiu de stocare",
    "FTP": "FTP",
    "Email account": "Cont email",
    "Email accounts": "Conturi email",
    "Database": "Bază de date",
    "Databases": "Baze de date",
    "Shared hosting": "Găzduire partajată",
    "VPS": "VPS",
    "Dedicated server": "Server dedicat",
    "Control panel": "Panou de control",
    "Virtualmin": "Virtualmin",
    "e-Factura": "e-Factura",
    "ANAF": "ANAF",
    "RON": "RON",
    "EUR": "EUR",
    "USD": "USD",
    "cPanel": "cPanel",
    "Plesk": "Plesk",
    # Audit / GDPR
    "Audit log": "Jurnal de audit",
    "Audit trail": "Traseu de audit",
    "Data export": "Export de date",
    "Data deletion": "Ștergere de date",
    "Consent": "Consimțământ",
    "GDPR": "GDPR",
    "Privacy policy": "Politică de confidențialitate",
    "Terms of service": "Termeni și condiții",
    "Data processing": "Prelucrarea datelor",
    "Personal data": "Date cu caracter personal",
    "Data controller": "Operator de date",
    # Notifications / emails
    "Notification": "Notificare",
    "Notifications": "Notificări",
    "Email notification": "Notificare prin email",
    "Send email": "Trimiteți email",
    "Unsubscribe": "Dezabonați-vă",
    "Subscribe": "Abonați-vă",
    # Standard error messages
    "An error occurred. Please try again.": "A apărut o eroare. Vă rugăm să încercați din nou.",
    "Operation completed successfully.": "Operațiunea a fost finalizată cu succes.",
    "Access denied.": "Acces refuzat.",
    "Not found.": "Nu a fost găsit.",
    "Permission denied.": "Permisiune refuzată.",
    "Session expired. Please log in again.": "Sesiunea a expirat. Vă rugăm să vă autentificați din nou.",
    "You do not have permission to perform this action.": "Nu aveți permisiunea de a efectua această acțiune.",
    "Invalid credentials.": "Date de autentificare invalide.",
    "Your account has been locked.": "Contul dvs. a fost blocat.",
    "Too many failed attempts.": "Prea multe încercări eșuate.",
    "Something went wrong. Please try again later.": "Ceva a mers greșit. Vă rugăm să încercați mai târziu.",
    "Page not found.": "Pagina nu a fost găsită.",
    "Internal server error.": "Eroare internă a serverului.",
    # Staff / roles
    "Staff": "Personal",
    "Administrator": "Administrator",
    "Role": "Rol",
    "Roles": "Roluri",
    "Permission": "Permisiune",
    "Permissions": "Permisiuni",
    "Superuser": "Super-administrator",
    "Owner": "Proprietar",
    "Manager": "Manager",
    "Member": "Membru",
    # Dashboard / navigation
    "Dashboard": "Panou de control",
    "Reports": "Rapoarte",
    "Analytics": "Analiză",
    "Configuration": "Configurare",
    "Integration": "Integrare",
    "Integrations": "Integrări",
    "Webhook": "Webhook",
    "Webhooks": "Webhooks",
    "API key": "Cheie API",
    "API keys": "Chei API",
    "Token": "Token",
    "Secret": "Secret",
    "Home": "Acasă",
    "Overview": "Prezentare generală",
    "Summary": "Sumar",
    "Activity": "Activitate",
    "Recent activity": "Activitate recentă",
    "History": "Istoric",
    "Timeline": "Cronologie",
    # Time / date
    "Today": "Astăzi",
    "Yesterday": "Ieri",
    "Tomorrow": "Mâine",
    "This week": "Această săptămână",
    "This month": "Această lună",
    "This year": "Acest an",
    "Last 30 days": "Ultimele 30 de zile",
    "Last 7 days": "Ultimele 7 zile",
    "From": "De la",
    "To": "Până la",
    "Start date": "Dată de început",
    "End date": "Dată de sfârșit",
    "Created at": "Creat la",
    "Updated at": "Actualizat la",
    "Deleted at": "Șters la",
    # Form labels
    "First name": "Prenume",
    "Last name": "Nume de familie",
    "Full name": "Nume complet",
    "Title": "Titlu",
    "Subject": "Subiect",
    "Message": "Mesaj",
    "Content": "Conținut",
    "Body": "Corp",
    "Reply": "Răspundeți",
    "Comment": "Comentariu",
    "Comments": "Comentarii",
    "Attachment": "Atașament",
    "Attachments": "Atașamente",
    "Priority": "Prioritate",
    "Category": "Categorie",
    "Categories": "Categorii",
    "Tag": "Etichetă",
    "Tags": "Etichete",
    "Label": "Etichetă",
    "Type": "Tip",
    "Kind": "Fel",
    "Format": "Format",
    "Language": "Limbă",
    "Locale": "Localizare",
    "Timezone": "Fus orar",
    "Currency code": "Cod monedă",
    # Pagination
    "Page": "Pagină",
    "of": "din",
    "per page": "pe pagină",
    "Show": "Afișați",
    "Showing": "Se afișează",
    "results": "rezultate",
    "No results found.": "Nu s-au găsit rezultate.",
    "No results.": "Niciun rezultat.",
    "No data available.": "Nu există date disponibile.",
    "Empty": "Gol",
    # SLA / support
    "Open": "Deschis",
    "Closed": "Închis",
    "Resolved": "Rezolvat",
    "In progress": "În progres",
    "On hold": "În așteptare",
    "Escalated": "Escaladat",
    "SLA": "SLA",
    "Response time": "Timp de răspuns",
    "Resolution time": "Timp de rezoluție",
    "First response": "Primul răspuns",
    "Assigned to": "Atribuit la",
    "Assigned": "Atribuit",
    "Unassigned": "Neatribuit",
    # Provisioning
    "Provision": "Provizionare",
    "Provisioning": "Provizionare",
    "Deploy": "Implementați",
    "Deployment": "Implementare",
    "Server": "Server",
    "Servers": "Servere",
    "Service": "Serviciu",
    "Services": "Servicii",
    "Plan": "Plan",
    "Plans": "Planuri",
    "Resource": "Resursă",
    "Resources": "Resurse",
    "Limit": "Limită",
    "Usage": "Utilizare",
    "Quota": "Cotă",
    # Romanian-specific
    "Romanian": "Român",
    "Romania": "România",
    "Bucharest": "București",
    "Cod poștal": "Cod poștal",
    "Județ": "Județ",
    "Registrar": "Registrar",
    "ROTLD": "ROTLD",
    "Registrant": "Registrant",
    "Contact": "Contact",
    "Contacts": "Contacte",
    "Technical contact": "Contact tehnic",
    "Administrative contact": "Contact administrativ",
    "Billing contact": "Contact facturare",
}

# ---------------------------------------------------------------------------
# Dictionary engine — regex patterns (first match wins)
# ---------------------------------------------------------------------------

PATTERN_TRANSLATIONS: list[tuple[str, str]] = [
    # Required field errors
    (r"^(.+) is required\.$", r"\1 este obligatoriu."),
    (r"^(.+) is required$", r"\1 este obligatoriu"),
    # Invalid field errors
    (r"^Invalid (.+)\.$", r"\1 invalid(ă)."),
    (r"^Invalid (.+)$", r"\1 invalid(ă)"),
    # Enter a valid X
    (r"^Enter a valid (.+)\.$", r"Introduceți un(o) \1 valid(ă)."),
    # Plural count patterns
    (r"^(\d+) (.+) found\.$", r"Au fost găsite \1 \2."),
    (r"^(\d+) (.+) selected\.$", r"\1 \2 selectat(e)."),
    # Successfully X-ed
    (r"^(.+) successfully created\.$", r"\1 a fost creat(ă) cu succes."),
    (r"^(.+) successfully updated\.$", r"\1 a fost actualizat(ă) cu succes."),
    (r"^(.+) successfully deleted\.$", r"\1 a fost șters(ă) cu succes."),
    (r"^(.+) was created successfully\.$", r"\1 a fost creat(ă) cu succes."),
    (r"^(.+) was updated successfully\.$", r"\1 a fost actualizat(ă) cu succes."),
    (r"^(.+) was deleted successfully\.$", r"\1 a fost șters(ă) cu succes."),
    (r"^(.+) has been created\.$", r"\1 a fost creat(ă)."),
    (r"^(.+) has been updated\.$", r"\1 a fost actualizat(ă)."),
    (r"^(.+) has been deleted\.$", r"\1 a fost șters(ă)."),
    (r"^(.+) has been saved\.$", r"\1 a fost salvat(ă)."),
    # Cannot / could not
    (r"^Cannot (.+)\.$", r"Nu se poate \1."),
    (r"^Could not (.+)\.$", r"Nu s-a putut \1."),
    # Please X
    (r"^Please enter (.+)\.$", r"Introduceți \1."),
    (r"^Please select (.+)\.$", r"Selectați \1."),
    (r"^Please provide (.+)\.$", r"Furnizați \1."),
    (r"^Please enter a valid (.+)\.$", r"Introduceți un(o) \1 valid(ă)."),
    # The X is/was
    (r"^The (.+) is invalid\.$", r"\1 este invalid(ă)."),
    (r"^The (.+) was not found\.$", r"\1 nu a fost găsit(ă)."),
    (r"^The (.+) does not exist\.$", r"\1 nu există."),
    (r"^The (.+) is required\.$", r"\1 este obligatoriu(ă)."),
    # Add/Create/Edit/Delete/View/Manage X  — noun phrases only (no auxiliary verbs)
    # Require the object to be a short noun phrase: no "is/are/was/were/has/have/will/been"
    (r"^Add (\w[\w\s\-\/]{0,40})$", r"Adăugați \1"),
    (r"^Create (\w[\w\s\-\/]{0,40})$", r"Creați \1"),
    (r"^Edit (\w[\w\s\-\/]{0,40})$", r"Editați \1"),
    (r"^Delete (\w[\w\s\-\/]{0,40})$", r"Ștergeți \1"),
    (r"^Update (\w[\w\s\-\/]{0,40})$", r"Actualizați \1"),
    (r"^View (\w[\w\s\-\/]{0,40})$", r"Vizualizați \1"),
    (r"^Manage (\w[\w\s\-\/]{0,40})$", r"Gestionați \1"),
    (r"^Search (\w[\w\s\-\/]{0,40})$", r"Căutați \1"),
    (r"^Filter by (\w[\w\s\-\/]{0,40})$", r"Filtrați după \1"),
    (r"^Filter (\w[\w\s\-\/]{0,40})$", r"Filtrați \1"),
    (r"^Export (\w[\w\s\-\/]{0,40})$", r"Exportați \1"),
    (r"^Download (\w[\w\s\-\/]{0,40})$", r"Descărcați \1"),
    (r"^Upload (\w[\w\s\-\/]{0,40})$", r"Încărcați \1"),
    (r"^Send (\w[\w\s\-\/]{0,40})$", r"Trimiteți \1"),
    (r"^List (\w[\w\s\-\/]{0,40})$", r"Listă \1"),
    (r"^New (\w[\w\s\-\/]{0,40})$", r"\1 nou(ă)"),
    # X not found
    (r"^(.+) not found\.$", r"\1 nu a fost găsit(ă)."),
    (r"^(.+) not found$", r"\1 nu a fost găsit(ă)"),
    # No X found / available
    (r"^No (.+) found\.$", r"Nu s-a găsit niciun(o) \1."),
    (r"^No (.+) found$", r"Nu s-a găsit niciun(o) \1"),
    (r"^No (.+) available\.$", r"Nu există niciun(o) \1 disponibil(ă)."),
    (r"^No (.+) yet\.$", r"Nu există încă niciun(o) \1."),
    # X list / details / history
    (r"^(.+) list$", r"Listă \1"),
    (r"^(.+) details$", r"Detalii \1"),
    (r"^(.+) history$", r"Istoric \1"),
    (r"^(.+) overview$", r"Prezentare generală \1"),
    (r"^(.+) summary$", r"Sumar \1"),
    # Failed to X
    (r"^Failed to (.+)\.$", r"Eroare la \1."),
    (r"^Failed to (.+)$", r"Eroare la \1"),
    # Error X / An error
    (r"^An error occurred while (.+)\.$", r"A apărut o eroare în timp ce \1."),
    (r"^Error: (.+)$", r"Eroare: \1"),
    # X already exists
    (r"^(.+) already exists\.$", r"\1 există deja."),
    (r"^(.+) already exists$", r"\1 există deja"),
    (r"^A (.+) with this (.+) already exists\.$", r"Un(o) \1 cu acest(ă) \2 există deja."),
    # Confirmation messages
    (r"^Are you sure you want to delete (.+)\?$", r"Sigur doriți să ștergeți \1?"),
    (r"^Are you sure you want to (.+)\?$", r"Sigur doriți să \1?"),
    # Status is/was
    (r"^(.+) is active\.$", r"\1 este activ(ă)."),
    (r"^(.+) is inactive\.$", r"\1 este inactiv(ă)."),
    (r"^(.+) is pending\.$", r"\1 este în așteptare."),
    (r"^(.+) is enabled\.$", r"\1 este activat(ă)."),
    (r"^(.+) is disabled\.$", r"\1 este dezactivat(ă)."),
    # X has been X-ed
    (r"^(.+) has been activated\.$", r"\1 a fost activat(ă)."),
    (r"^(.+) has been deactivated\.$", r"\1 a fost dezactivat(ă)."),
    (r"^(.+) has been approved\.$", r"\1 a fost aprobat(ă)."),
    (r"^(.+) has been rejected\.$", r"\1 a fost respins(ă)."),
    (r"^(.+) has been cancelled\.$", r"\1 a fost anulat(ă)."),
    (r"^(.+) has been completed\.$", r"\1 a fost finalizat(ă)."),
    # Password Reset / Email
    (r"^Password Reset (.+)$", r"Resetare parolă \1"),
    (r"^(.+) Password Reset$", r"\1 Resetare parolă"),
    # Select / choose X — noun phrases only
    (r"^Select (\w[\w\s\-\/]{0,40})$", r"Selectați \1"),
    (r"^Choose (\w[\w\s\-\/]{0,40})$", r"Alegeți \1"),
    # Your X has been Y — only short noun phrases + single past-participle word
    (r"^Your (\w[\w\s]{0,30}) has been (\w+)\.$", r"\1 dvs. a fost \2."),
    # X for X — noun phrase only
    (r"^Request for (\w[\w\s\-\/]{0,40})$", r"Solicitare pentru \1"),
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class TranslationEntry:
    msgid: str
    msgstr_suggested: str
    source_file: str
    status: str = "pending"
    source: str = "dictionary"
    confidence: str = "high"
    comment: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "msgid": self.msgid,
            "msgstr_suggested": self.msgstr_suggested,
            "source_file": self.source_file,
            "status": self.status,
            "source": self.source,
            "confidence": self.confidence,
        }
        if self.comment:
            d["comment"] = self.comment
        return d


@dataclass
class AppStats:
    app: str
    translated: int = 0
    total: int = 0

    @property
    def percent(self) -> float:
        return (self.translated / self.total * 100) if self.total else 0.0


@dataclass
class GenerateConfig:
    """Options for the generate subcommand."""

    po_file: Path
    output: Path
    use_claude: bool = False
    model: str = "claude-haiku-4-5"
    batch_size: int = 30
    include_fuzzy: bool = False
    dry_run: bool = False


# ---------------------------------------------------------------------------
# Dictionary engine
# ---------------------------------------------------------------------------


class DictionaryEngine:
    """Translate strings using exact matches and regex patterns."""

    def translate(self, msgid: str) -> tuple[str | None, str, str]:
        """Return (translation, source, confidence) or (None, ...) if no match."""
        # Exact match
        if msgid in EXACT_TRANSLATIONS:
            return EXACT_TRANSLATIONS[msgid], "dictionary", "high"

        # Case-insensitive exact
        lower = msgid.lower()
        for key, val in EXACT_TRANSLATIONS.items():
            if key.lower() == lower:
                return val, "dictionary", "medium"

        # Pattern match
        for pattern, replacement in PATTERN_TRANSLATIONS:
            try:
                if re.match(pattern, msgid, flags=re.IGNORECASE):
                    result = re.sub(pattern, replacement, msgid, flags=re.IGNORECASE)
                    if result != msgid:
                        return result, "pattern", "medium"
            except re.error:
                continue

        return None, "none", "low"


# ---------------------------------------------------------------------------
# Placeholder / format validation
# ---------------------------------------------------------------------------

_PRINTF_RE = re.compile(r"%(?:\([^)]+\))?[sdiouxXeEfFgGcr%]|%\d+\$[sdiouxXeEfFgG]|\{[^}]*\}")
_EXPLANATION_PREFIXES = ("Translation:", "Translated:", "Romanian:", "RO:", "EN:")


def _extract_placeholders(text: str) -> list[str]:
    return _PRINTF_RE.findall(text)


def validate_translation(msgid: str, msgstr: str) -> list[str]:
    """Return list of validation error strings (empty if OK)."""
    errors: list[str] = []

    if not msgstr:
        return errors

    # Check for explanation text prefix
    stripped = msgstr.strip()
    errors.extend(
        f"Translation starts with explanation prefix '{p}'" for p in _EXPLANATION_PREFIXES if stripped.startswith(p)
    )

    # Check printf / format placeholders are preserved
    src_ph = sorted(_extract_placeholders(msgid))
    dst_ph = sorted(_extract_placeholders(msgstr))
    if src_ph != dst_ph:
        errors.append(f"Placeholder mismatch: source={src_ph} target={dst_ph}")

    # Sanity check: msgstr should not contain English meta-commentary
    english_giveaways = [" is a ", " refers to ", "This means ", "In Romanian ", "Note: "]
    errors.extend(f"Possible English explanation detected: '{g}'" for g in english_giveaways if g in msgstr)

    return errors


# ---------------------------------------------------------------------------
# Claude AI engine
# ---------------------------------------------------------------------------

CLAUDE_SYSTEM_PROMPT = """You are a professional Romanian translator specializing in software localization for a hosting provider platform called PRAHO (PragmaticHost).

Key glossary — use these exact Romanian terms:
- CUI = Cod Unic de Înregistrare (Romanian company tax ID)
- TVA = Taxa pe Valoarea Adăugată (VAT)
- Proformă = Proforma invoice
- Factură = Invoice (plural: Facturi)
- Abonament = Subscription
- Comandă = Order
- Produs = Product
- Client = Customer
- Domeniu = Domain
- Găzduire = Hosting
- Bilet de suport = Support ticket
- Furnizor = Provider
- Panou de control = Dashboard
- Autentificare = Login/Authentication
- Înregistrare = Registration
- Facturare = Billing
- Abonament = Subscription
- ANAF = Agenția Națională de Administrare Fiscală
- e-Factura = e-Factura (Romanian e-invoicing system)

Translation rules:
1. Preserve ALL format specifiers exactly as-is: %(name)s, %s, %d, {variable}, etc.
2. Use formal Romanian address (dvs. register for user-facing strings)
3. Use subjunctive/imperative for instructions: "Introduceți", "Selectați", "Confirmați"
4. Do NOT add any prefix like "Translation:", "Romanian:", or explanatory text
5. Match the register and tone of the source string
6. For technical terms without standard Romanian equivalents, keep the English term
7. Romanian uses diacritics: ă, â, î, ș, ț (with cedilla: ș ț, not comma below)

Respond ONLY with a JSON object where keys are the original English strings and values are the Romanian translations:
{"original string": "traducere română", ...}
"""


def translate_with_claude(
    entries: list[str],
    model: str = "claude-haiku-4-5",
    batch_size: int = 30,
) -> dict[str, str]:
    """Send entries to claude CLI in batches, return msgid -> translation map."""
    if not shutil.which("claude"):
        logger.warning("⚠️  claude CLI not found — skipping AI translation")
        return {}

    results: dict[str, str] = {}
    total_batches = (len(entries) + batch_size - 1) // batch_size

    for i in range(0, len(entries), batch_size):
        batch = entries[i : i + batch_size]
        batch_num = i // batch_size + 1
        logger.info("✅ Processing AI batch %d/%d (%d strings)", batch_num, total_batches, len(batch))

        prompt_data = json.dumps(batch, ensure_ascii=False, indent=2)
        prompt = f"Translate these strings to Romanian:\n{prompt_data}"

        try:
            result = subprocess.run(
                [
                    "claude",
                    "-p",
                    "--model",
                    model,
                    "--output-format",
                    "json",
                    "--system-prompt",
                    CLAUDE_SYSTEM_PROMPT,
                    prompt,
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.returncode != 0:
                logger.warning(
                    "⚠️  claude CLI error for batch %d: %s",
                    batch_num,
                    result.stderr[:200],
                )
                continue

            # claude --output-format json wraps in {"type":"result","result":"..."}
            raw = result.stdout.strip()
            try:
                outer = json.loads(raw)
                inner_text: str = outer.get("result", raw) if isinstance(outer, dict) else raw
            except json.JSONDecodeError:
                inner_text = raw

            # Extract JSON object from response (may have markdown code fences)
            json_match = re.search(r"\{.*\}", inner_text, re.DOTALL)
            if not json_match:
                logger.warning("⚠️  No JSON object found in claude response for batch %d", batch_num)
                continue

            translations: dict[str, str] = json.loads(json_match.group())
            results.update(translations)

        except subprocess.TimeoutExpired:
            logger.warning("⚠️  claude CLI timed out for batch %d", batch_num)
        except json.JSONDecodeError as exc:
            logger.warning("⚠️  Failed to parse claude JSON for batch %d: %s", batch_num, exc)
        except Exception as exc:
            logger.warning("⚠️  Unexpected error for batch %d: %s", batch_num, exc)

    return results


# ---------------------------------------------------------------------------
# .po file helpers
# ---------------------------------------------------------------------------


def _entry_source_file(entry: polib.POEntry) -> str:
    """Return the first occurrence string, e.g. 'apps/billing/models.py:42'."""
    if entry.occurrences:
        file_path, line = entry.occurrences[0]
        return f"{file_path}:{line}"
    return ""


def _extract_app_name(source: str) -> str:
    """Extract app name from occurrence path like 'apps/billing/models.py:42'."""
    match = re.search(r"apps/([^/]+)/", source)
    if match:
        return match.group(1)
    # Fallback: first path component of the file portion
    file_part = source.split(":", maxsplit=1)[0]
    parts = Path(file_part).parts
    return parts[0] if parts else "unknown"


def load_po(po_file: Path) -> polib.POFile:
    return polib.pofile(str(po_file))


def get_untranslated_entries(
    po: polib.POFile,
    include_fuzzy: bool = False,
) -> list[polib.POEntry]:
    """Return entries with empty msgstr (and optionally fuzzy entries)."""
    entries: list[polib.POEntry] = []
    for entry in po:
        if entry.obsolete:
            continue
        is_fuzzy = "fuzzy" in entry.flags
        if is_fuzzy and not include_fuzzy:
            continue
        if is_fuzzy and include_fuzzy:
            entries.append(entry)
            continue
        if not entry.msgstr or not entry.msgstr.strip():
            entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# Stats mode
# ---------------------------------------------------------------------------


def cmd_stats(po_file: Path, include_fuzzy: bool = False) -> None:
    """Print per-app translation coverage statistics."""
    po = load_po(po_file)

    app_stats: dict[str, AppStats] = defaultdict(lambda: AppStats(app=""))

    for entry in po:
        if entry.obsolete:
            continue
        source = _entry_source_file(entry)
        app = _extract_app_name(source)
        if app not in app_stats:
            app_stats[app] = AppStats(app=app)

        stats = app_stats[app]
        stats.total += 1

        is_fuzzy = "fuzzy" in entry.flags
        has_translation = bool(entry.msgstr and entry.msgstr.strip())
        if has_translation and (not is_fuzzy or include_fuzzy):
            stats.translated += 1

    if not app_stats:
        print("No entries found.")
        return

    sorted_apps = sorted(app_stats.values(), key=lambda s: s.app)
    total_translated = sum(s.translated for s in sorted_apps)
    total_all = sum(s.total for s in sorted_apps)

    col_w = 28
    header = f"{'App':<{col_w}} {'Translated':>12} {'Total':>8} {'Coverage':>10}  Progress"
    separator = "-" * (len(header) + 22)
    print(f"\nTranslation coverage: {po_file}")
    print(separator)
    print(header)
    print(separator)

    for stats in sorted_apps:
        bar_filled = int(stats.percent / 5)
        bar = "#" * bar_filled + "." * (20 - bar_filled)
        print(f"{stats.app:<{col_w}} {stats.translated:>12} {stats.total:>8} {stats.percent:>9.1f}%  [{bar}]")

    print(separator)
    overall_pct = (total_translated / total_all * 100) if total_all else 0.0
    print(f"{'TOTAL':<{col_w}} {total_translated:>12} {total_all:>8} {overall_pct:>9.1f}%")
    print()


# ---------------------------------------------------------------------------
# Generate mode
# ---------------------------------------------------------------------------


def cmd_generate(cfg: GenerateConfig) -> None:
    """Generate YAML review file from untranslated .po entries."""
    po_file = cfg.po_file
    po = load_po(po_file)
    untranslated = get_untranslated_entries(po, include_fuzzy=cfg.include_fuzzy)

    if not untranslated:
        logger.info("✅ No untranslated entries found in %s", po_file)
        return

    logger.info("✅ Found %d untranslated entries", len(untranslated))

    engine = DictionaryEngine()
    result_entries: list[TranslationEntry] = []
    ai_candidates: list[polib.POEntry] = []

    for entry in untranslated:
        source_file = _entry_source_file(entry)
        translation, source, confidence = engine.translate(entry.msgid)

        if translation:
            errors = validate_translation(entry.msgid, translation)
            if errors:
                logger.warning("⚠️  Validation failed for '%s': %s", entry.msgid[:60], errors)
                confidence = "low"

            result_entries.append(
                TranslationEntry(
                    msgid=entry.msgid,
                    msgstr_suggested=translation,
                    source_file=source_file,
                    status="pending",
                    source=source,
                    confidence=confidence,
                )
            )
        else:
            ai_candidates.append(entry)

    dict_count = len(result_entries)
    logger.info(
        "✅ Dictionary matched %d/%d entries; %d remaining for AI",
        dict_count,
        len(untranslated),
        len(ai_candidates),
    )

    # AI translations for remaining entries
    if ai_candidates and cfg.use_claude:
        msgids = [e.msgid for e in ai_candidates]
        ai_translations = translate_with_claude(msgids, model=cfg.model, batch_size=cfg.batch_size)

        for entry in ai_candidates:
            source_file = _entry_source_file(entry)
            ai_translation = ai_translations.get(entry.msgid, "")

            if ai_translation:
                errors = validate_translation(entry.msgid, ai_translation)
                confidence = "low" if errors else "medium"
                if errors:
                    logger.warning("⚠️  AI validation failed for '%s': %s", entry.msgid[:60], errors)

                result_entries.append(
                    TranslationEntry(
                        msgid=entry.msgid,
                        msgstr_suggested=ai_translation,
                        source_file=source_file,
                        status="pending",
                        source="ai",
                        confidence=confidence,
                    )
                )
            else:
                result_entries.append(
                    TranslationEntry(
                        msgid=entry.msgid,
                        msgstr_suggested="",
                        source_file=source_file,
                        status="pending",
                        source="none",
                        confidence="low",
                    )
                )
    else:
        # No AI: add all remaining as empty/unmatched
        result_entries.extend(
            TranslationEntry(
                msgid=entry.msgid,
                msgstr_suggested="",
                source_file=_entry_source_file(entry),
                status="pending",
                source="none",
                confidence="low",
            )
            for entry in ai_candidates
        )

    # Build YAML document
    document: dict[str, Any] = {
        "metadata": {
            "po_file": str(po_file),
            "generated_at": dt.datetime.now(tz=dt.UTC).isoformat(),
            "source": "ai" if cfg.use_claude else "dictionary",
            "total_entries": len(result_entries),
        },
        "entries": [e.to_dict() for e in result_entries],
    }

    yaml_header = "# Generated by translate_po.py — review entries and set status: approved before applying\n"
    yaml_body = yaml.dump(
        document,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=120,
    )
    yaml_text = yaml_header + yaml_body

    if cfg.dry_run:
        print(yaml_text[:3000])
        print(f"\n[dry-run] Would write {len(result_entries)} entries to {cfg.output}")
        return

    cfg.output.write_text(yaml_text, encoding="utf-8")
    logger.info("✅ Written %d entries to %s", len(result_entries), cfg.output)


# ---------------------------------------------------------------------------
# Apply mode
# ---------------------------------------------------------------------------


def cmd_apply(
    review_yaml: Path,
    compile_messages: bool = False,
    dry_run: bool = False,
    backup: bool = False,
) -> None:
    """Apply approved translations from YAML back to .po file."""
    raw = yaml.safe_load(review_yaml.read_text(encoding="utf-8"))

    if not isinstance(raw, dict):
        logger.error("🔥 Invalid YAML format: expected a mapping at top level")
        sys.exit(1)

    metadata = raw.get("metadata", {})
    po_file_path = Path(metadata.get("po_file", ""))

    if not po_file_path.exists():
        logger.error("🔥 .po file not found: %s", po_file_path)
        sys.exit(1)

    entries_raw: list[dict[str, Any]] = raw.get("entries", [])
    approved = [e for e in entries_raw if e.get("status") == "approved"]

    if not approved:
        logger.warning("⚠️  No entries with status: approved found in %s", review_yaml)
        return

    logger.info("✅ Found %d approved translations", len(approved))

    # Validate ALL approved entries before touching any file
    invalid_msgs: list[str] = []
    for entry in approved:
        msgid = entry.get("msgid", "")
        msgstr = entry.get("msgstr_suggested", "")
        errors = validate_translation(msgid, msgstr)
        if errors:
            invalid_msgs.append(f"  '{msgid[:60]}': {errors}")

    if invalid_msgs:
        logger.error(
            "🔥 Validation failed for %d entries:\n%s",
            len(invalid_msgs),
            "\n".join(invalid_msgs),
        )
        sys.exit(1)

    if backup and not dry_run:
        bak = po_file_path.with_suffix(".po.bak")
        shutil.copy2(po_file_path, bak)
        logger.info("✅ Backup created: %s", bak)

    po = load_po(po_file_path)
    po_map: dict[str, polib.POEntry] = {entry.msgid: entry for entry in po}

    applied = 0
    skipped = 0

    for entry_data in approved:
        msgid = entry_data.get("msgid", "")
        msgstr = entry_data.get("msgstr_suggested", "")
        source = entry_data.get("source", "")

        if not msgid or not msgstr:
            skipped += 1
            continue

        po_entry = po_map.get(msgid)
        if po_entry is None:
            logger.warning("⚠️  msgid not in .po file (skipping): '%s'", msgid[:60])
            skipped += 1
            continue

        if dry_run:
            print(f"[dry-run] '{msgid[:60]}' -> '{msgstr[:60]}'")
            applied += 1
            continue

        po_entry.msgstr = msgstr

        # Mark AI-generated entries with a comment
        if source == "ai":
            existing = po_entry.comment or ""
            if "AI-generated" not in existing:
                po_entry.comment = (existing + "\nAI-generated").strip()

        # Remove fuzzy flag so the entry is considered translated
        if "fuzzy" in po_entry.flags:
            po_entry.flags.remove("fuzzy")

        applied += 1

    if dry_run:
        logger.info("[dry-run] Would apply %d translations (%d skipped)", applied, skipped)
        return

    po.save(str(po_file_path))
    logger.info("✅ Saved %d translations to %s (%d skipped)", applied, po_file_path, skipped)

    if compile_messages:
        _compile_messages(po_file_path)


def _compile_messages(po_file_path: Path) -> None:
    """Compile .po to .mo using manage.py compilemessages or msgfmt."""
    logger.info("✅ Compiling %s", po_file_path.name)
    locale_dir = po_file_path.parents[2]  # …/locale/ro/LC_MESSAGES -> …/locale

    # Walk upward from locale dir to find manage.py
    manage_py: Path | None = None
    search = locale_dir
    for _ in range(6):
        candidate = search / "manage.py"
        if candidate.exists():
            manage_py = candidate
            break
        search = search.parent

    if manage_py:
        subprocess.run(
            [sys.executable, str(manage_py), "compilemessages"],
            cwd=str(manage_py.parent),
            check=True,
        )
        logger.info("✅ compilemessages completed")
    elif shutil.which("msgfmt"):
        mo_path = po_file_path.with_suffix(".mo")
        subprocess.run(["msgfmt", str(po_file_path), "-o", str(mo_path)], check=True)
        logger.info("✅ msgfmt completed -> %s", mo_path)
    else:
        logger.warning("⚠️  Neither manage.py nor msgfmt found — skipping compilation")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="translate_po.py",
        description="Smart Romanian translation tool for Django .po files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # stats
    stats_p = sub.add_parser("stats", help="Show per-app translation coverage statistics")
    stats_p.add_argument("po_file", type=Path, help="Path to .po file")
    stats_p.add_argument(
        "--include-fuzzy",
        action="store_true",
        help="Count fuzzy entries as translated",
    )

    # generate
    gen_p = sub.add_parser(
        "generate",
        help="Generate review YAML from untranslated entries",
    )
    gen_p.add_argument("po_file", type=Path, help="Path to .po file")
    gen_p.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("review.yaml"),
        help="Output YAML file (default: review.yaml)",
    )
    gen_p.add_argument(
        "--claude",
        action="store_true",
        help="Use Claude AI for entries the dictionary cannot match",
    )
    gen_p.add_argument(
        "--model",
        default="claude-haiku-4-5",
        help="Claude model slug (default: claude-haiku-4-5)",
    )
    gen_p.add_argument(
        "--batch-size",
        type=int,
        default=30,
        metavar="N",
        help="Strings per Claude API call (default: 30)",
    )
    gen_p.add_argument(
        "--include-fuzzy",
        action="store_true",
        help="Include fuzzy entries in generation",
    )
    gen_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview output without writing the YAML file",
    )

    # apply
    apply_p = sub.add_parser(
        "apply",
        help="Apply approved translations from review YAML to .po",
    )
    apply_p.add_argument("review_yaml", type=Path, help="Path to review YAML file")
    apply_p.add_argument(
        "--compile",
        action="store_true",
        help="Run compilemessages after applying translations",
    )
    apply_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be applied without writing",
    )
    apply_p.add_argument(
        "--backup",
        action="store_true",
        help="Create .po.bak before modifying the .po file",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "stats":
        cmd_stats(args.po_file, include_fuzzy=args.include_fuzzy)

    elif args.command == "generate":
        cmd_generate(
            GenerateConfig(
                po_file=args.po_file,
                output=args.output,
                use_claude=args.claude,
                model=args.model,
                batch_size=args.batch_size,
                include_fuzzy=args.include_fuzzy,
                dry_run=args.dry_run,
            )
        )

    elif args.command == "apply":
        cmd_apply(
            review_yaml=args.review_yaml,
            compile_messages=args.compile,
            dry_run=args.dry_run,
            backup=args.backup,
        )


if __name__ == "__main__":
    main()
