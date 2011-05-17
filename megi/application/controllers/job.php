<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

class Job extends CI_controller {
  
  // Overwrite contructor
  function __construct()
  {
    parent::__construct();
    //load config
    $this->config->load('megi');
    //load libary
    $this->load->library('tank_auth');
    //load model
    $this->load->model('job/job_model', 'jobs', TRUE);
    //load ci helpers
    $this->load->helper(array('form', 'download'));
    //load project helpers
    $this->load->helper(array('rdns'));
  }

  // Index Page for Jobs Listing all Jobs by the user
  function index()
  {
    // Availibel Jobs for the current user
    $data['jobs'] = $this->jobs->get_for_current_user();

    // Possible job types
    $data['types'] = $this->config->item('modules');

    // Create page
    $this->load->view('header');
    $this->load->view('job/_form', $data);
    $this->load->view('job/list', $data);
    $this->load->view('footer');
  }

  // Create a Job
  function create()
  {
    $this->jobs->create();
    redirect('job');    
  }

  // View a Job by ID
  function view($id)
  {
    // Get requested job and only show if it belongs to the user
    $job = $this->jobs->find($id);
    if($job->user_id == $this->tank_auth->get_user_id())
    {
      $data['job'] = $job;
    } 
    else 
    {
      redirect('job');
    }

    //Create page
    $this->load->view('header');
    $this->load->view('job/view', $data);
    $this->load->view('footer');
  }

  // Handle Job
  function start($id)
  {
    $job = $this->jobs->find_for_user($id);
    // Check if job belongs to current user
    if($job)
    {
      // Check if type is availible and run
      if(array_key_exists($job->type, $this->config->item('modules')))
      {
        // files to use
        $specfile = $this->config->item('spec_path').'/'.$job->id.'.spec';
        $resfile = $this->config->item('result_path').'/'.$job->id.'.res';
        touch($resfile);
        chmod($resfile, 0666);

        //write out spec to use
        $infile = fopen($specfile, 'w');
        fwrite($infile, $job->spec);
        fclose($infile);

        //start job via helper
        $start_func = $job->type.'_start';
        $tool_path = $this->config->item('tool_path');
        if($start_func($job, $specfile, $resfile, $tool_path))
        {
          //job started
          $this->jobs->set_start_date($id);
          echo $job->type.' job started';
        }
        else 
        {
          echo $job->type.' job start failed';
        }
      } 
      else 
      {
        echo 'Module '.$job->type.' is not availible';
      }
    } 
    else 
    {
      redirect('job');
    }
  }

  function result($id)
  {
    $job = $this->jobs->find_for_user($id);
    // Job needs to be started
    if($job && $job->start_date != '0000-00-00 00:00:00')
    {
      $data = file_get_contents($this->config->item('result_path').'/'.$job->id.'.res');
      if($job->name)
      {
        $name = $job->name.'_result.csv';
      }
      else
      {
        $name = $job->type.'_'.$job->id.'_result.csv';
      }
      force_download($name, $data);
    }
    else
    {
      if($job->name)
      {
        echo $job->name.' not started yet';
      }
      else
      {
        echo $job->id.' not started yet';
      }
    }
  }

  function spec($id)
  {
    $job = $this->jobs->find_for_user($id);
    if($job)
    {
      $data['job'] = $job;
    }
    else
    {
      redirect('job');
    }
    // Get Spec
    $data['spec'] = file_get_contents($this->config->item('spec_path').'/'.$job->id.'.spec');

    // Create page
    $this->load->view('header');
    $this->load->view('job/spec', $data);
    $this->load->view('footer');
  }


}
/* End Job Controller */
