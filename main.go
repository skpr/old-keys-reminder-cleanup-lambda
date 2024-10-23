package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	sesTypes "github.com/aws/aws-sdk-go-v2/service/ses/types"
)

type defaultedUser struct {
	UserName  string
	Email     string
	Key       iamTypes.AccessKeyMetadata
	OlderThan string
}

func main() {
	lambda.Start(HandleLabdaEvent)
}

func HandleLabdaEvent(ctx context.Context) error {
	sess, err := config.LoadDefaultConfig(ctx)

	if err != nil {
		fmt.Println("Couldn't load configuration. Have you set up your AWS account?")
		fmt.Println(err)
		return nil
	}

	iamClient := iam.NewFromConfig(sess)
	sesClient := ses.NewFromConfig(sess)

	// Get SES configuration from lambda env variables
	var (
		fromAddress = os.Getenv("EMAIL_FROM_ADDRESS")
		dryRun      = os.Getenv("DRY_RUN")
	)

	defaultedUsers, err := getDefaultedUsers(iamClient)
	if err != nil {
		fmt.Println("Error getting users and their keys:", err)
		return nil
	}

	for _, user := range defaultedUsers {
		// email defaultedUsers
		sendEmail(user.Email, fromAddress, sesClient, user.OlderThan)
		if isOld, _ := isKeyOld(user.Key, 100); isOld {
			// delete the key
			if dryRun == "--dry-run" {
				deleteKeys(*user.Key.AccessKeyId, user.UserName, iamClient)
			}
		}
	}

	return nil

}

// getDefaultedUsers retrieves all IAM users and their access keys, checks if the keys are older than 60 days,
// and performs actions based on the key age and user details.
func getDefaultedUsers(iamClient *iam.Client) ([]defaultedUser, error) {
	users, err := listAllUsers(iamClient)
	if err != nil {
		return nil, err
	}

	var defaultedUsers []defaultedUser
	for _, user := range users {
		email, err := getUserEmailTag(iamClient, user)
		if err != nil {
			return nil, err
		}
		if email == "" {
			continue
		}

		keys, err := listAllAccessKeys(iamClient, user)
		if err != nil {
			return nil, err
		}

		for _, key := range keys {
			if old, days := isKeyOld(key); old {
				fmt.Println("Access key", *key.AccessKeyId, "for user", *user.UserName, "is older than 60 days.")
				defaultedUser := defaultedUser{
					UserName:  *user.UserName,
					Email:     email,
					Key:       key,
					OlderThan: days,
				}
				defaultedUsers = append(defaultedUsers, defaultedUser)
			}
		}
	}
	return defaultedUsers, nil
}

// listAllUsers retrieves all IAM users in the account.
func listAllUsers(iamClient *iam.Client) ([]iamTypes.User, error) {
	input := &iam.ListUsersInput{}
	var users []iamTypes.User
	for {
		result, err := iamClient.ListUsers(context.TODO(), input)
		if err != nil {
			return nil, fmt.Errorf("error listing users: %w", err)
		}
		users = append(users, result.Users...)
		if result.Marker == nil {
			break
		}
		input.Marker = result.Marker
	}
	return users, nil
}

// getUserEmailTag retrieves the email tag for a user.
func getUserEmailTag(iamClient *iam.Client, user iamTypes.User) (string, error) {
	input := &iam.ListUserTagsInput{
		UserName: user.UserName,
	}
	for {
		result, err := iamClient.ListUserTags(context.TODO(), input)
		if err != nil {
			return "", fmt.Errorf("error listing tags: %w", err)
		}
		for _, tag := range result.Tags {
			if *tag.Key == "email" {
				return *tag.Value, nil
			}
		}
		if result.Marker == nil {
			break
		}
		input.Marker = result.Marker
	}
	return "", nil
}

// listAllAccessKeys retrieves all access keys for a user.
func listAllAccessKeys(iamClient *iam.Client, user iamTypes.User) ([]iamTypes.AccessKeyMetadata, error) {
	input := &iam.ListAccessKeysInput{
		UserName: user.UserName,
	}
	var keys []iamTypes.AccessKeyMetadata
	for {
		result, err := iamClient.ListAccessKeys(context.TODO(), input)
		if err != nil {
			return nil, fmt.Errorf("error listing access keys: %w", err)
		}
		keys = append(keys, result.AccessKeyMetadata...)
		if result.Marker == nil {
			break
		}
		input.Marker = result.Marker
	}
	return keys, nil
}

// isKeyOld checks if an access key is older than a specified number of days.
func isKeyOld(key iamTypes.AccessKeyMetadata, olderThan ...int) (bool, string) {
	if len(olderThan) > 0 && key.CreateDate.Add(time.Duration(olderThan[0])*24*time.Hour).Before(time.Now()) {
		return true, fmt.Sprintf("%d", olderThan[0])
	} else if key.CreateDate.Add(57 * 24 * time.Hour).Before(time.Now()) {
		return true, "57"
	} else if key.CreateDate.Add(50 * 24 * time.Hour).Before(time.Now()) {
		return true, "50"
	} else {
		return false, ""
	}
}

// deleteKeys deletes an access key.
func deleteKeys(accessKeyId string, userName string, svc *iam.Client) (Keys []iamTypes.AccessKeyMetadata, err error) {
	input := &iam.DeleteAccessKeyInput{
		AccessKeyId: aws.String(accessKeyId),
		UserName:    aws.String(userName),
	}

	result, err := svc.DeleteAccessKey(context.TODO(), input)
	if err != nil {
		fmt.Println("Error deleting access key,", err)
		return
	}

	fmt.Println(result)
	return
}

// sendEmail sends an email to a recipient.
func sendEmail(toEmail string, fromEmail string, sesClient *ses.Client, days string) error {
	input := &ses.SendEmailInput{
		Destination: &sesTypes.Destination{
			ToAddresses: []string{
				toEmail, // replace with the recipient's email
			},
		},
		Message: &sesTypes.Message{
			Body: &sesTypes.Body{
				Text: &sesTypes.Content{
					Data: aws.String("Your secret keys are older than " + days + " days and will be deleted."), // replace with your message
				},
			},
			Subject: &sesTypes.Content{
				Data: aws.String("Secret Key Expiration Warning"), // replace with your subject
			},
		},
		Source: aws.String(fromEmail), // replace with your email
	}

	_, err := sesClient.SendEmail(context.TODO(), input)
	if err != nil {
		fmt.Println("Error sending email,", err)
		return err
	}

	fmt.Println("Email sent successfully.")
	return nil
}
