# 🛡️ IDE Auto-Formatting Prevention Guide

## ⚠️ The Problem: IDE Auto-Formatting Breaking Django Templates

IDE auto-formatting can remove spaces around comparison operators in Django templates, causing:

```
TemplateSyntaxError: Could not parse the remainder: '==VALUE' from 'variable==VALUE'
```

## 🔧 Complete Prevention Solution

### 1. ✅ VS Code Configuration (`.vscode/settings.json`)

**Disables auto-formatting for Django templates:**
```json
{
  "[django-html]": {
    "editor.formatOnSave": false,
    "editor.formatOnPaste": false,
    "editor.formatOnType": false
  },
  "[html]": {
    "editor.formatOnSave": false,
    "editor.formatOnPaste": false,
    "editor.formatOnType": false
  },
  "files.associations": {
    "*.html": "django-html",
    "**/templates/**/*.html": "django-html"
  }
}
```

### 2. ✅ EditorConfig (`.editorconfig`)

**Prevents other editors from auto-formatting templates:**
```ini
[*.{html,htm}]
# 🚨 Django templates should NOT be auto-formatted
indent_style = space
indent_size = 2
trim_trailing_whitespace = false
insert_final_newline = false
```

### 3. ✅ Prettier Ignore (`.prettierignore`)

**Completely excludes templates from Prettier:**
```
templates/
*.html
**/*.html
```

### 4. ✅ Pre-Commit Hook (`.git/hooks/pre-commit`)

**Blocks commits with template syntax errors:**
- Automatically runs template validation
- Shows helpful error messages
- Provides fix commands
- Warns about IDE auto-formatting

### 5. ✅ Automated Detection & Fixing

**Scripts available:**
```bash
# Check for issues
make check-templates
python scripts/fix_template_comparisons.py --check

# Fix automatically
make fix-templates
python scripts/fix_template_comparisons.py
```

## 🚨 Common Auto-Formatting Triggers

1. **Format on Save** - Most dangerous, formats everything automatically
2. **Format on Paste** - Breaks copied template code
3. **Format on Type** - Reformats as you type
4. **Prettier Extension** - Very aggressive HTML formatting
5. **Manual Format Document** - `Cmd+Shift+F` / `Ctrl+Shift+F`

## 📋 IDE-Specific Solutions

### PyCharm/IntelliJ IDEA
```xml
<!-- In .idea/codeStyleSettings.xml -->
<component name="ProjectCodeStyleConfiguration">
  <state>
    <option name="PER_PROJECT_SETTINGS">
      <value>
        <HTML>
          <option name="FORMATTER_OFF_TAG" value="{% comment %}" />
          <option name="FORMATTER_ON_TAG" value="{% endcomment %}" />
        </HTML>
      </value>
    </option>
  </state>
</component>
```

### Sublime Text
```json
// In Preferences > Settings
{
  "auto_format_on_save": false,
  "html_format_on_save": false,
  "format_on_paste": false
}
```

### Vim/Neovim
```vim
" In ~/.vimrc or ~/.config/nvim/init.vim
autocmd FileType html,htmldjango setlocal formatoptions-=t
autocmd FileType html,htmldjango let b:autoformat_autoindent=0
```

## 🔍 How to Identify Auto-Formatting Issues

### Signs it was IDE auto-formatting:
- Multiple comparison operators affected at once
- File modified timestamp is very recent
- All spacing issues in same file
- Happens after opening/saving file
- Consistent pattern across templates

### Detection in our script:
```bash
python scripts/fix_template_comparisons.py --check
```

Will show warnings like:
```
⚠️  File modified recently - could be IDE auto-formatting
⚠️  Multiple operators affected - check IDE settings
```

## 🎯 Team Guidelines

### ✅ Safe Operations:
- Edit templates manually (but be careful with spaces!)
- Use `make fix-templates` after any template changes
- Run `make check-templates` before commits
- Copy-paste with manual spacing verification

### ❌ Dangerous Operations:
- Format Document (`Cmd+Shift+F`) on templates
- Format on Save enabled for HTML files
- Using Prettier on templates
- Auto-indenting entire template files

## 🚀 Quick Fix Workflow

If you encounter template syntax errors:

1. **Immediate fix:**
   ```bash
   make fix-templates
   ```

2. **Check your IDE settings:**
   - Verify `.vscode/settings.json` is correct
   - Disable format-on-save for HTML
   - Check if Prettier is running on templates

3. **Commit with validation:**
   ```bash
   git add .
   git commit -m "fix: template syntax"
   # Pre-commit hook will validate
   ```

## 🛡️ Defense in Depth Strategy

1. **Prevention** - IDE settings prevent auto-formatting
2. **Detection** - Scripts detect issues when they occur
3. **Validation** - Pre-commit hooks block bad commits
4. **Automation** - Easy fix commands available
5. **Education** - Clear documentation and warnings

This multi-layered approach ensures template syntax issues are caught and fixed quickly, with clear guidance on preventing them in the future.
