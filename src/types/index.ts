export enum ItemType {
    LOGIN = "Login",
    SECURE_NOTE = "Secure Note",
    CREDIT_CARD = "Credit Card",
    API_KEY = "API Key",
    CUSTOM = "Custom",
}

export enum FolderPermissions {
    EDIT = "edit",
    READ_ONLY = "read-only",
}

export enum WorkspaceRole {
    ADMIN = "admin",
    MANAGER = "manager",
    MEMBER = "member",
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
