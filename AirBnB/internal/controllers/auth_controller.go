// Package controllers handles the business logic and request/response handling
// for different features of the application
package controllers

import (
	"AirBnB/internal/database"
	"AirBnB/internal/utils"
	"fmt"
	"html"
	"mime/multipart"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

// AuthController handles all authentication related operations
// It requires a database connection to perform user operations
type AuthController struct {
	db database.Service // Database interface for user operations
}

// NewAuthController creates a new instance of AuthController
// This follows the dependency injection pattern
func NewAuthController(db database.Service) *AuthController {
	return &AuthController{db: db}
}

// RegisterRequest defines the expected JSON structure for user registration
// The `validate` tags specify validation rules for each field
type RegisterRequest struct {
	Email        string                `json:"email" validate:"required,email,max=255"`    // Must be a valid email
	Password     string                `json:"password" validate:"required,min=8,max=255"` // Minimum 8 characters
	FirstName    string                `json:"firstName" validate:"required,max=255"`      // Cannot be empty
	LastName     string                `json:"lastName" validate:"required,max=255"`       // Cannot be empty
	Country      string                `json:"country" validate:"required,max=50"`
	Phone        string                `json:"phone" validate:"required,max=20,min=10,e164"`
	ProfileImage *multipart.FileHeader `json:"profileImage"` // File header for the profile image
}

// Register handles new user registration
// POST /auth/register
func (ac *AuthController) Register(c *fiber.Ctx) error {
	// Parse user details from the form-data request
	email := c.FormValue("email")
	password := c.FormValue("password")
	firstName := c.FormValue("firstName")
	lastName := c.FormValue("lastName")
	country := c.FormValue("country")
	phone := c.FormValue("phone")

	// Validate required fields
	validate := validator.New()
	if err := validate.Var(email, "required,email,max=255"); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": "Invalid email format",
		})
	}

	if err := validate.Var(password, "required,min=8,max=255"); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": "Password must be between 8 and 255 characters",
		})
	}

	if err := validate.Var(firstName, "required,max=255"); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": "First name is required and must be under 255 characters",
		})
	}

	if err := validate.Var(lastName, "required,max=255"); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": "Last name is required and must be under 255 characters",
		})
	}

	if err := validate.Var(country, "required,max=50"); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": "Country is required and must be under 50 characters",
		})
	}

	if err := validate.Var(phone, "required,max=20,min=10,e164"); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": "Invalid phone number format",
		})
	}

	// Handle profile image upload
	file, err := c.FormFile("profileImage")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Profile image is required",
		})
	}

	// Generate unique filename and save the file
	filename := utils.GenerateUniqueFilename(file.Filename)
	filePath := fmt.Sprintf("uploads/profile_images/%s", filename)
	if err := c.SaveFile(file, filePath); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to save profile image",
		})
	}

	// Check if the user already exists
	existingUser, err := ac.db.GetUserByEmail(email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error checking user existence",
		})
	}

	if existingUser != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "Email already registered",
		})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error hashing password",
		})
	}

	// Create new user
	newUser := database.User{
		Email:       email,
		Password:    string(hashedPassword),
		FirstName:   html.EscapeString(firstName),
		LastName:    html.EscapeString(lastName),
		Country:     html.EscapeString(country),
		Phone:       html.EscapeString(phone),
		Profile_Url: fmt.Sprintf("/uploads/profile_images/%s", filename), // Save the file URL
	}

	if err := ac.db.CreateNewUser(&newUser); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error creating user",
		})
	}

	token, err := utils.GenerateToken(newUser.ID, newUser.Email, newUser.FirstName)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error generating token",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "User registered successfully",
		"token":   token,
		"user": fiber.Map{
			"email":      newUser.Email,
			"firstName":  newUser.FirstName,
			"lastName":   newUser.LastName,
			"country":    newUser.Country,
			"phone":      newUser.Phone,
			"profileUrl": newUser.Profile_Url,
		},
	})
}

// LoginRequest defines the expected JSON structure for user login
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"` // Must be a valid email
	Password string `json:"password" validate:"required"`    // Cannot be empty
}

// Login authenticates a user and returns a JWT token
// POST /auth/login
func (ac *AuthController) Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	validate := validator.New()
	if err := validate.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": err.Error(),
		})
	}

	// Get user by email and password
	user, err := ac.db.GetUserByEmailAndPassword(req.Email, req.Password)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error during login",
		})
	}

	if user == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid email or password",
		})
	}

	// Generate JWT token
	token, err := utils.GenerateToken(user.ID, user.Email, user.FirstName)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error generating token",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Login successful",
		"token":   token,
		"user": fiber.Map{
			"email":      user.Email,
			"firstName":  user.FirstName,
			"lastName":   user.LastName,
			"country":    user.Country,
			"phone":      user.Phone,
			"profileUrl": user.Profile_Url,
		},
	})
}

// TODO: Verify credentials against database

// TODO: Generate JWT token for authenticated user

// ForgotPasswordRequest defines the expected JSON structure for password reset
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"` // Must be a valid email
}

// ForgotPassword initiates the password reset process
// POST /auth/forgot-password
func (ac *AuthController) ForgotPassword(c *fiber.Ctx) error {
	var req ForgotPasswordRequest
	// Parse the JSON request body into our ForgotPasswordRequest struct
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// TODO: Generate unique reset token
	// TODO: Send reset email to user

	return c.JSON(fiber.Map{
		"message": "Password reset instructions sent to email",
	})
}
