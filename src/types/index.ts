export enum ReBACNamespace {
    USERS = "users",
    WORKSPACES = "workspaces",
    FOLDERS = "folders",
    ITEMS = "items",
}

export enum ReBACRelation {
    // Owner & Role
    OWNER = "owner",
    ADMIN = "admin",
    MANAGER = "manager",
    MEMBER = "member",

    // Parent
    PARENT = "parent",

    // Share
    EDITOR = "editor",
    VIEWER = "viewer",
}

export enum ItemType {
    LOGIN = "Login",
    SECURE_NOTE = "Secure Note",
    CREDIT_CARD = "Credit Card",
    API_KEY = "API Key",
    CUSTOM = "Custom",
}

export enum CustomFieldType {
    TEXT = "text",
    MULTILINE_TEXT = "multiline_text",
    HIDDEN_TEXT = "hidden_text",
    SECURED_NOTE = "secured_note",
    WEBSITE = "website",
    EMAIL = "email",
    ADDRESS = "address",
    PHONE = "phone",
    DATE = "date",
    PIN_CODE = "pin_code",
}
