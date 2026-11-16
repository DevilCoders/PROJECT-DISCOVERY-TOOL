"""Personal-data field names across languages and data formats: snake_case, camelCase,
PascalCase, kebab-case and dotted keys, in code, schemas, markup and configuration."""
from __future__ import annotations

from pathlib import Path

import pytest

from project_discovery.analyzers.security.privacy import DataExposureAnalyzer
from project_discovery.models import FileRecord

SYNTAXES = [
    ("user.py", "class User:\n    first_name: str\n    last_name: str\n", {"first_name", "last_name"}),
    ("User.java", "public class User { private String firstName; private String lastName; }\n", {"first_name", "last_name"}),
    ("user.go", "type User struct {\n\tFirstName string `json:\"first_name\"`\n\tEmail string\n}\n", {"first_name", "email"}),
    ("user.rs", "struct User { first_name: String, phone_number: String }\n", {"first_name", "phone"}),
    ("user.ts", "interface User { givenName: string; familyName: string }\n", {"first_name", "last_name"}),
    ("user.js", "const user = { firstName, middleName, surname };\n", {"first_name", "middle_name", "last_name"}),
    ("User.cs", "public string FirstName { get; set; }\npublic DateTime DateOfBirth { get; set; }\n", {"first_name", "date_of_birth"}),
    ("User.kt", "data class User(val firstName: String, val accountId: String)\n", {"first_name", "account_id"}),
    ("User.swift", "struct User { let givenName: String; let postalCode: String }\n", {"first_name", "address"}),
    ("user.php", "$user->first_name = $request->input('last_name');\n", {"first_name", "last_name"}),
    ("user.rb", "attr_accessor :first_name, :username\n", {"first_name", "username"}),
    ("User.scala", "case class User(firstName: String, iban: String)\n", {"first_name", "account_id"}),
    ("user.dart", "class User { final String firstName; final String phoneNumber; }\n", {"first_name", "phone"}),
    ("user.c", "struct user { char first_name[64]; char ssn[12]; };\n", {"first_name", "government_id"}),
    ("user.cpp", "std::string firstName; std::string dateOfBirth;\n", {"first_name", "date_of_birth"}),
    ("User.m", "@property NSString *firstName;\n@property NSString *emailAddress;\n", {"first_name", "email"}),
    ("user.lua", "local user = { first_name = nil, user_name = nil }\n", {"first_name", "username"}),
    ("user.pl", "my %user = (first_name => undef, email_address => undef);\n", {"first_name", "email"}),
    ("user.ex", 'schema "users" do\n  field :first_name, :string\n  field :birth_date, :date\nend\n', {"first_name", "date_of_birth"}),
    ("User.hs", "data User = User { firstName :: String, lastName :: String }\n", {"first_name", "last_name"}),
    ("users.R", "users <- data.frame(first_name = c(), zip_code = c())\n", {"first_name", "address"}),
    ("user.jl", "struct User\n    first_name::String\n    full_name::String\nend\n", {"first_name", "full_name"}),
    ("user.sql", "CREATE TABLE users (first_name TEXT, last_name TEXT, date_of_birth DATE);\n",
     {"first_name", "last_name", "date_of_birth"}),
    ("schema.graphql", "type User {\n  firstName: String\n  emailAddress: String\n}\n", {"first_name", "email"}),
    ("user.proto", "message User {\n  string first_name = 1;\n  string passport_number = 2;\n}\n", {"first_name", "government_id"}),
    ("user.avsc", '{"type": "record", "fields": [{"name": "firstName", "type": "string"}]}\n', {"first_name"}),
    ("user.schema.json", '{"properties": {"givenName": {"type": "string"}, "telephone": {"type": "string"}}}\n',
     {"first_name", "phone"}),
    ("users.csv", "first_name,last_name,email\n", {"first_name", "last_name", "email"}),
    ("user.yaml", "user:\n  first-name: x\n  home-address: y\n", {"first_name", "address"}),
    ("user.toml", '[user]\nfirst_name = ""\nmiddle_name = ""\n', {"first_name", "middle_name"}),
    ("user.ini", "[user]\nfirst.name =\nlast.name =\n", {"first_name", "last_name"}),
    ("user.properties", "user.first.name=\nuser.tax.id=\n", {"first_name", "government_id"}),
    ("user.xml", "<user><FirstName/><LastName/><DriversLicenseNumber/></user>\n", {"first_name", "last_name", "government_id"}),
    ("form.html", '<input name="first-name"><input name="billing-address">\n', {"first_name", "address"}),
    ("Form.vue", '<template><input v-model="form.firstName"></template>\n', {"first_name"}),
    ("Form.jsx", '<input name="lastName" />\n', {"last_name"}),
    ("main.tf", 'variable "customer_number" {}\n', {"account_id"}),
    ("user.ps1", "$FirstName = Read-Host\n$MobileNumber = Read-Host\n", {"first_name", "phone"}),
    ("user.sh", "FIRST_NAME=\nLAST_NAME=\n", {"first_name", "last_name"}),
    ("user.env", "USER_NAME=\nPHONE_NUMBER=\n", {"username", "phone"}),
    ("schema.prisma", "model User {\n  firstName String\n  bankAccount String\n}\n", {"first_name", "account_id"}),
    ("schema.ts", "const schema = z.object({ firstName: z.string(), dob: z.date() })\n", {"first_name", "date_of_birth"}),
    ("User.vb", "Public Property FirstName As String\nPublic Property Birthday As Date\n", {"first_name", "date_of_birth"}),
    ("user.erl", "-record(user, {first_name, msisdn}).\n", {"first_name", "phone"}),
]


def _categories(tmp_path: Path, filename: str, content: str) -> set[str]:
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, Path(filename).suffix, "Text", file_type="text")
    analyzer = DataExposureAnalyzer()
    assert analyzer.supports(record)
    found = next((item for item in analyzer.analyze(path, record) if item.title.startswith("Personal-data field")), None)
    if found is None:
        return set()
    return {name.strip() for name in found.detail.split("categories: ", 1)[1].split(".", 1)[0].split(",")}


def test_more_than_forty_syntaxes_are_covered():
    assert len(SYNTAXES) >= 40 and len({Path(name).suffix for name, _, _ in SYNTAXES}) >= 38


@pytest.mark.parametrize(("filename", "content", "expected"), SYNTAXES, ids=[item[0] for item in SYNTAXES])
def test_field_names_are_found_in_each_syntax(tmp_path: Path, filename, content, expected):
    assert expected <= _categories(tmp_path, filename, content)


@pytest.mark.parametrize("content", [
    "ip_address = '10.0.0.1'\nmac_address = x\n",   # an address that is not a person's
    "first_name_label = 'First name'\n",            # another field that only starts with the name
    "username_regex = r'^[a-z]+$'\n",
    "mobile = True\n",                               # a platform, not a phone number
    "account_type = 'savings'\n",
])
def test_names_that_are_not_personal_data(tmp_path: Path, content):
    assert _categories(tmp_path, "settings.py", content) == set()
