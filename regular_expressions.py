import re

# password validation
# at least 8 characters, any letters, or numbers, $%#@

pattern = re.compile(r"[a-zA-Z0-9$%#@]{8,}\d$")
password = "jkshfjkdhfdsjk$%4535"

a = pattern.search(password)
check = pattern.fullmatch(password)


print(a)