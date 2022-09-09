export AWS_ACCOUNT_ID := $(shell aws sts get-caller-identity --query 'Account' --output text)
.PHONY: clean lambroll/logs lambroll/deploy

bootstrap: ../cmd/ls3viewer/*.go ../*.go ../go.*
	GOARCH=amd64 GOOS=linux go build -o bootstrap ../cmd/ls3viewer/*.go

clean:
	rm -f bootstrap
	rm -f ls3viewer_dummy.zip

lambroll/deploy: bootstrap
	lambroll --log-level debug deploy
	$(MAKE) lambroll/logs

lambroll/logs:
	lambroll logs --follow --format=short


.PHONY: terraform/init
terraform/init:
	terraform providers lock \
		-platform=darwin_amd64 \
		-platform=darwin_arm64 \
		-platform=linux_amd64 \
		-platform=linux_arm64 \
		-platform=windows_amd64
	terraform init


.PHONY: terraform/plan
terraform/plan:
	terraform plan


.PHONY: terraform/apply
terraform/apply:
	terraform apply
