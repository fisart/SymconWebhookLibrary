<?php

declare(strict_types=1);

class WebhookLibrary extends IPSModule
{
    public function Create()
    {
        // Never delete this line!
        parent::Create();

        // Properties
        // Properties
        $this->RegisterPropertyBoolean('UsePasswordProtection', false);
        $this->RegisterPropertyInteger('SecretsManagerID', 0);
        $this->RegisterVariableString('LibraryHtml', $this->Translate('Webhook Library'), '~HTMLBox', 0);
        $this->DisableAction('LibraryHtml');
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

        // Update HTML visualization
        $this->UpdateLibraryHtml();
    }

    protected function ProcessHookData()
    {
        // 1. Optional Authentication (SecretsManager)
        $usePasswordProtection = $this->ReadPropertyBoolean('UsePasswordProtection');
        $instanceID = $this->ReadPropertyInteger('SecretsManagerID');

        if ($usePasswordProtection) {
            if ($instanceID > 0 && @IPS_InstanceExists($instanceID)) {
                if (function_exists('SEC_IsPortalAuthenticated')) {
                    if (!SEC_IsPortalAuthenticated($instanceID)) {
                        $currentUrl = $_SERVER['REQUEST_URI'] ?? '';
                        $loginUrl = '/hook/secrets_' . (string)$instanceID . '?portal=1&return=' . urlencode($currentUrl);
                        header('Location: ' . $loginUrl);
                        return;
                    }
                } else {
                    echo 'Error: Password protection is enabled, but the Secrets Manager function SEC_IsPortalAuthenticated is not available.';
                    return;
                }
            } else {
                echo 'Error: Password protection is enabled, but no valid Secrets Manager instance is configured.';
                return;
            }
        }

        // Keep HTMLBox in sync when the page is opened via webhook
        $this->UpdateLibraryHtml();

        echo $this->BuildLibraryHtml(true);
    }

    private function UpdateLibraryHtml()
    {
        $html = $this->BuildLibraryHtml(false);
        SetValueString($this->GetIDForIdent('LibraryHtml'), $html);
    }

    private function BuildLibraryHtml(bool $fullPage): string
    {
        $data = $this->GetHookLists();
        $internalHooks = $data['internalHooks'];
        $userHooks = $data['userHooks'];

        $content = '';
        $content .= "<style>
                    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; background-color: #f4f4f9; margin: 0; }
                    h2, h3 { color: #333; }
                    ul { list-style-type: none; padding: 0; margin: 0 0 20px 0; }
                    li { background: #fff; margin: 5px 0; border: 1px solid #ddd; border-radius: 5px; transition: background 0.2s; }
                    li:hover { background: #e9ecef; }
                    a { display: block; padding: 15px; text-decoration: none; color: #0078d7; font-weight: bold; }
                    .empty { color: #666; font-style: italic; margin-bottom: 20px; }
                </style>";

        $content .= '<h2>Available Links</h2>';

        $content .= '<h3>Internal WebHooks</h3>';
        if (count($internalHooks) === 0) {
            $content .= "<div class='empty'>No internal hooks found.</div>";
        } else {
            $content .= '<ul>';
            foreach ($internalHooks as $entry) {
                $escapedUrl = htmlspecialchars($entry['url'], ENT_QUOTES, 'UTF-8');
                $content .= '<li><a href="' . $escapedUrl . '" target="_blank" rel="noopener noreferrer">' . $escapedUrl . '</a></li>';
            }
            $content .= '</ul>';
        }

        $content .= '<h3>Registered WebHooks</h3>';
        if (count($userHooks) === 0) {
            $content .= "<div class='empty'>No registered webhooks found.</div>";
        } else {
            $content .= '<ul>';
            foreach ($userHooks as $entry) {
                $escapedUrl = htmlspecialchars($entry['url'], ENT_QUOTES, 'UTF-8');
                $content .= '<li><a href="' . $escapedUrl . '" target="_blank" rel="noopener noreferrer">' . $escapedUrl . '</a></li>';
            }
            $content .= '</ul>';
        }

        if ($fullPage) {
            return '<!DOCTYPE html><html><head><title>Webhook Library</title><meta name="viewport" content="width=device-width, initial-scale=1"></head><body>' . $content . '</body></html>';
        }

        return $content;
    }

    private function GetHookLists(): array
    {
        $userHooks = [];
        $internalHooks = [];

        $ids = IPS_GetInstanceListByModuleID('{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}');
        if (count($ids) === 0) {
            return [
                'internalHooks' => [],
                'userHooks'     => []
            ];
        }

        $webHookControlID = $ids[0];

        // User-defined hooks from property
        $hooksRaw = IPS_GetProperty($webHookControlID, 'Hooks');
        $hooks = json_decode($hooksRaw, true);

        if (is_array($hooks)) {
            foreach ($hooks as $row) {
                if (!is_array($row) || !isset($row['Hook']) || !is_string($row['Hook'])) {
                    continue;
                }

                $hook = trim($row['Hook']);
                if ($hook === '') {
                    continue;
                }

                $url = (strpos($hook, '/') === 0) ? $hook : '/hook/' . ltrim($hook, '/');
                $userHooks[$url] = [
                    'url'  => $url,
                    'hook' => $hook,
                    'row'  => $row
                ];
            }
        }

        // Internal hooks from configuration form
        $formRaw = IPS_GetConfigurationForm($webHookControlID);
        $form = json_decode($formRaw, true);

        if (is_array($form)) {
            $scanNode = function ($node, $path = '') use (&$scanNode, &$internalHooks) {
                if (!is_array($node)) {
                    return;
                }

                if (isset($node['values']) && is_array($node['values'])) {
                    $caption = isset($node['caption']) && is_string($node['caption']) ? $node['caption'] : '';
                    $name = isset($node['name']) && is_string($node['name']) ? $node['name'] : '';

                    $isInternalSection =
                        (stripos($caption, 'internal') !== false) ||
                        (stripos($name, 'internal') !== false) ||
                        (stripos($path, 'internal') !== false);

                    if ($isInternalSection) {
                        foreach ($node['values'] as $row) {
                            if (!is_array($row) || !isset($row['Hook']) || !is_string($row['Hook'])) {
                                continue;
                            }

                            $hook = trim($row['Hook']);
                            if ($hook === '') {
                                continue;
                            }

                            $url = (strpos($hook, '/') === 0) ? $hook : '/hook/' . ltrim($hook, '/');
                            $internalHooks[$url] = [
                                'url'  => $url,
                                'hook' => $hook,
                                'row'  => $row
                            ];
                        }
                    }
                }

                foreach ($node as $key => $value) {
                    if (is_array($value)) {
                        $scanNode($value, $path . '/' . (string)$key);
                    }
                }
            };

            $scanNode($form);
        }

        ksort($internalHooks, SORT_NATURAL | SORT_FLAG_CASE);
        ksort($userHooks, SORT_NATURAL | SORT_FLAG_CASE);

        return [
            'internalHooks' => $internalHooks,
            'userHooks'     => $userHooks
        ];
    }
    private function RegisterHook($WebHook)
    {
        // Correct GUID for your system
        $ids = IPS_GetInstanceListByModuleID("{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}");

        // REMOVED: Auto-creation logic (Guideline 2.iv violation)

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
            // Log error instead of creating instance
            $this->LogMessage("Error: WebHook Control Instance not found! Please check your Core Instances.", KL_ERROR);
        }
    }
}
