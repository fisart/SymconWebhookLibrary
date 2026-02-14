<?php

declare(strict_types=1);

class WebhookLibrary extends IPSModule
{
    public function Create()
    {
        // Never delete this line!
        parent::Create();

        // Properties
        $this->RegisterPropertyInteger('SecretsManagerID', 0);
    }

    public function Destroy()
    {
        // Never delete this line!
        parent::Destroy();
    }

    public function ApplyChanges()
    {
        // Never delete this line!
        parent::ApplyChanges();

        // Register the Webhook
        $this->RegisterHook('/hook/library');
    }

    protected function ProcessHookData()
    {
        // 1. Authentication (SecretsManager)
        $instanceID = $this->ReadPropertyInteger('SecretsManagerID');

        // Only check if an instance ID is configured
        if ($instanceID > 0 && @IPS_InstanceExists($instanceID)) {
            // Check if the SecretsManager function exists to prevent fatal errors
            if (function_exists('SEC_IsPortalAuthenticated')) {
                if (!SEC_IsPortalAuthenticated($instanceID)) {
                    $currentUrl = $_SERVER['REQUEST_URI'] ?? '';
                    // Redirect to SecretsManager Login
                    $loginUrl = "/hook/secrets_" . (string)$instanceID . "?portal=1&return=" . urlencode($currentUrl);
                    header("Location: " . $loginUrl);
                    return;
                }
            }
        }

        // 2. Retrieve Webhook List
        // UPDATED GUID based on your system diagnostic
        $ids = IPS_GetInstanceListByModuleID("{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}");

        if (count($ids) === 0) {
            echo "Error: WebHook Control instance not found.";
            return;
        }

        // Get the raw Hooks list from the Core Instance
        $hooks = json_decode(IPS_GetProperty($ids[0], "Hooks"), true);

        // 3. Generate HTML Output
        $html = "<!DOCTYPE html><html><head><title>Webhook Library</title>";
        $html .= "<meta name='viewport' content='width=device-width, initial-scale=1'>";
        $html .= "<style>
                    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; background-color: #f4f4f9; }
                    h2 { color: #333; }
                    ul { list-style-type: none; padding: 0; }
                    li { background: #fff; margin: 5px 0; border: 1px solid #ddd; border-radius: 5px; transition: background 0.2s; }
                    li:hover { background: #e9ecef; }
                    a { display: block; padding: 15px; text-decoration: none; color: #0078d7; font-weight: bold; }
                  </style>";
        $html .= "</head><body>";
        $html .= "<h2>Available Webhooks</h2>";
        $html .= "<ul>";

        // Loop through all hooks and create links
        if (is_array($hooks)) {
            foreach ($hooks as $hook) {
                $url = $hook['Hook'];
                // Simple safety escaping
                $displayText = htmlspecialchars($url);
                $html .= "<li><a href=\"$url\">$displayText</a></li>";
            }
        }

        $html .= "</ul></body></html>";

        // 4. Send Output
        echo $html;
    }

    private function RegisterHook($WebHook)
    {
        // Correct GUID for your system
        $ids = IPS_GetInstanceListByModuleID("{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}");

        if (count($ids) > 0) {
            $hooks = json_decode(IPS_GetProperty($ids[0], "Hooks"), true);
            $found = false;

            if (!is_array($hooks)) {
                $hooks = [];
                $this->LogMessage("Webhook list was empty/invalid. Creating new list.", KL_MESSAGE);
            }

            foreach ($hooks as $index => $hook) {
                if ($hook['Hook'] == $WebHook) {
                    if ($hook['TargetID'] == $this->InstanceID) {
                        return;
                    }
                    $hooks[$index]['TargetID'] = $this->InstanceID;
                    $found = true;
                    $this->LogMessage("Webhook '$WebHook' was taken over by this instance.", KL_MESSAGE);
                }
            }
            if (!$found) {
                $hooks[] = ["Hook" => $WebHook, "TargetID" => $this->InstanceID];
                $this->LogMessage("Webhook '$WebHook' was successfully created.", KL_MESSAGE);
            }
            IPS_SetProperty($ids[0], "Hooks", json_encode($hooks));
            IPS_ApplyChanges($ids[0]);
        } else {
            $this->LogMessage("Error: No WebHook Control Instance found!", KL_ERROR);
        }
    }
}
