#ifndef UNSAFE_API_BAN_H
#define UNSAFE_API_BAN_H

// Define SAFE_STR_BAN_UNSAFE_APIS in core modules to force migration to checked wrappers.
#ifdef SAFE_STR_BAN_UNSAFE_APIS

#define gets      UNSAFE_API_gets__use_fgets_or_copy_checked
#define strcpy    UNSAFE_API_strcpy__use_copy_checked
#define strcat    UNSAFE_API_strcat__use_format_checked_or_safe_concat
#define sprintf   UNSAFE_API_sprintf__use_format_checked
#define vsprintf  UNSAFE_API_vsprintf__use_format_checked

#endif

#endif
